import aiohttp
import json
import logging
import os
from .exceptions import TecnoalarmNotInitialized
from .constants import HDR_AUTH, HDR_APP_ID, HDR_ATYPE, HDR_TOKEN, HDR_LANG, HDR_VER


class _LoggedClientSession:
    def __init__(self, session: aiohttp.ClientSession, log_file: str):
        self._session = session
        self._logger = logging.getLogger("pytecnoalarm_tcs.http")
        if not self._logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s"
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

        self._log_headers = os.getenv("TCS_HTTP_LOG_HEADERS", "false").lower() == "true"
        self._log_body = os.getenv("TCS_HTTP_LOG_BODY", "true").lower() == "true"

    def _format_body(self, kwargs: dict) -> str | None:
        if not self._log_body:
            return None
        if "json" in kwargs:
            try:
                return json.dumps(kwargs["json"], ensure_ascii=False)
            except Exception:
                return str(kwargs["json"])
        if "data" in kwargs:
            try:
                return json.dumps(kwargs["data"], ensure_ascii=False)
            except Exception:
                return str(kwargs["data"])
        return None

    def _log_request(self, method: str, url: str, **kwargs) -> None:
        body = self._format_body(kwargs)
        if self._log_headers and "headers" in kwargs:
            self._logger.info("REQUEST: %s %s headers=%s body=%s", method, url, kwargs.get("headers"), body)
        else:
            self._logger.info("REQUEST: %s %s body=%s", method, url, body)
    
    async def _log_response(self, method: str, url: str, resp: aiohttp.ClientResponse) -> None:
        """Log response details (status, headers, body)"""
        status = resp.status
        headers = dict(resp.headers) if self._log_headers else None
        
        # Try to read response body
        body = None
        if self._log_body:
            try:
                # Peek at content without consuming it
                body_bytes = await resp.read()
                # Decode body
                try:
                    body_text = body_bytes.decode('utf-8')
                    # Try to format as JSON if possible
                    try:
                        body_json = json.loads(body_text)
                        body = json.dumps(body_json, ensure_ascii=False)
                    except (json.JSONDecodeError, ValueError):
                        # Not JSON, keep as text (limit to 500 chars)
                        body = body_text[:500] + ("..." if len(body_text) > 500 else "")
                except UnicodeDecodeError:
                    body = f"<binary data, {len(body_bytes)} bytes>"
                
                # Important: restore body for actual consumption by caller
                # We need to "put back" the content we read
                resp._body = body_bytes
            except Exception as e:
                body = f"<error reading body: {e}>"
        
        if self._log_headers and headers:
            self._logger.info("RESPONSE: %s %s status=%d headers=%s body=%s", method, url, status, headers, body)
        else:
            self._logger.info("RESPONSE: %s %s status=%d body=%s", method, url, status, body)

    class _LoggedResponse:
        """Wrapper around aiohttp.ClientResponse that logs on __aexit__"""
        def __init__(self, cm, logger_func, method: str, url: str):
            self._cm = cm
            self._logger_func = logger_func
            self._method = method
            self._url = url
            self._resp = None
        
        async def __aenter__(self):
            self._resp = await self._cm.__aenter__()
            return self._resp
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            # Log response before closing
            if self._resp:
                await self._logger_func(self._method, self._url, self._resp)
            return await self._cm.__aexit__(exc_type, exc_val, exc_tb)

    def request(self, method: str, url: str, **kwargs):
        self._log_request(method, url, **kwargs)
        cm = self._session.request(method, url, **kwargs)
        return self._LoggedResponse(cm, self._log_response, method, url)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def __getattr__(self, name):
        return getattr(self._session, name)


class TecnoalarmSession:
    def __init__(self, session: aiohttp.ClientSession):
        log_file = os.getenv("TCS_HTTP_LOG_FILE")
        if log_file:
            self._session = _LoggedClientSession(session, log_file)
        else:
            self._session = session

        # Handshake data
        self.account_base: str | None = None
        self.tcs_base: str | None = None

        # Auth data
        self.token: str | None = None
        self.app_id: str | None = None
        self.account_id: int | None = None
        
        # TCS-Token (obtained from PUT /tcsRC/app response)
        self.tcs_token: str | None = None
        self.tcs_token_expiration: int | None = None
        
        # Central data
        self.central_type: str | None = None  # e.g., "tp042"
        self.central_id: str | None = None    # e.g., "003236056"
        self.central_name: str | None = None  # e.g., "ALLARME CASA"
        self._central_activated: bool = False  # Track if monitor was called
        self.program_names: dict[int, str] = {}  # index -> name/description
        
        # PIN storage (encrypted in production)
        self._pin: str | None = None

    # ---------- state helpers ----------

    @property
    def is_handshaken(self) -> bool:
        return self.account_base is not None and self.tcs_base is not None

    @property
    def is_authenticated(self) -> bool:
        return self.token is not None and self.app_id is not None
    
    @property
    def is_central_ready(self) -> bool:
        return self.central_type is not None and self.central_id is not None

    def set_pin(self, pin: str) -> None:
        """Store PIN securely (should be encrypted in production)"""
        self._pin = pin

    def get_pin(self) -> str | None:
        """Retrieve stored PIN"""
        return self._pin

    # ---------- headers ----------

    def auth_headers(self) -> dict:
        """Build authentication headers (Auth + X-App-Id)"""
        if not self.is_authenticated:
            return {}
        return {
            HDR_AUTH: self.token,
            HDR_APP_ID: str(self.app_id),
        }
    
    def tcs_auth_headers(self) -> dict:
        """Build TCS authentication headers (Auth + TCS-Token + X-App-Id)"""
        headers = self.auth_headers()
        if self.tcs_token:
            headers["TCS-Token"] = self.tcs_token
        return headers

    def tcs_headers(self) -> dict:
        """Build TCS-specific headers (Auth + TCS-Token + atype + lang + ver + Accept)"""
        headers = self.tcs_auth_headers()
        headers.update({
            HDR_ATYPE: "app",
            HDR_LANG: "it",
            HDR_VER: "1.0",
            "Accept": "application/json, text/plain, */*",
        })
        return headers
    
    def set_tcs_token(self, token: str, expiration: int | None = None) -> None:
        """Store TCS-Token from PUT /tcsRC/app response"""
        self.tcs_token = token
        self.tcs_token_expiration = expiration

    def is_token_expired(self) -> bool:
        """Check if TCS-Token has expired."""
        if not self.tcs_token_expiration:
            return False  # No expiration info = assume valid
        import time
        # Handle milliseconds vs seconds
        expiration_seconds = self.tcs_token_expiration
        if expiration_seconds > 100000000000:  # Likely milliseconds (before year 5138)
            expiration_seconds = expiration_seconds / 1000
        return int(time.time()) > expiration_seconds

    def is_token_about_to_expire(self, seconds_threshold: int = 300) -> bool:
        """Check if TCS-Token will expire soon (within threshold seconds)."""
        if not self.tcs_token_expiration:
            return False
        import time
        # Handle milliseconds vs seconds
        expiration_seconds = self.tcs_token_expiration
        if expiration_seconds > 100000000000:  # Likely milliseconds
            expiration_seconds = expiration_seconds / 1000
        time_until_expiration = expiration_seconds - int(time.time())
        return 0 < time_until_expiration < seconds_threshold

    def get_token_expiration_str(self) -> str:
        """Get human-readable token expiration time."""
        if not self.tcs_token_expiration:
            return "Unknown"
        from datetime import datetime
        # Handle milliseconds vs seconds
        expiration_seconds = self.tcs_token_expiration
        if expiration_seconds > 100000000000:  # Likely milliseconds (before year 5138)
            expiration_seconds = expiration_seconds / 1000
        try:
            dt = datetime.fromtimestamp(expiration_seconds)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            # Fallback if still invalid
            return f"Invalid ({self.tcs_token_expiration})"

    # ---------- url builders ----------

    def account_url(self, path: str) -> str:
        if not self.account_base:
            raise TecnoalarmNotInitialized("Handshake not completed")
        return f"{self.account_base}{path}"

    def tcs_url(self, path: str) -> str:
        if not self.tcs_base:
            raise TecnoalarmNotInitialized("Handshake not completed")
        return f"{self.tcs_base}{path}"