import aiohttp
from .exceptions import TecnoalarmNotInitialized
from .constants import HDR_AUTH, HDR_APP_ID, HDR_ATYPE, HDR_TOKEN, HDR_LANG, HDR_VER


class TecnoalarmSession:
    def __init__(self, session: aiohttp.ClientSession):
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