import base64
import json
import aiohttp
from .exceptions import (
    TecnoalarmOTPRequired,
    TecnoalarmAuthError,
    TecnoalarmAPIError,
    TecnoalarmEmailNotFound,
    TecnoalarmPINRequired,
    TecnoalarmReauthRequired,
    TecnoalarmNotInitialized,
)
from .constants import (
    HANDSHAKE_URL,
    ACCOUNT_EMAIL_VALIDATION,
    ACCOUNT_LOGIN,
    TCS_TP_REGISTER,
    HTTP_207_MULTI_STATUS,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_412_PRECONDITION_FAILED,
)


class TecnoalarmAuth:
    def __init__(self, session):
        self._session = session
        self._central_data = None  # Will store central data for PIN registration

    # ---------- handshake ----------

    async def handshake(self) -> None:
        """
        Initial handshake to get account and TCS service endpoints.
        Response contains appID, entrypoints, and service tokens.
        """
        # Build headers for handshake
        headers = {
            "Accept": "application/json",
            "aType": "MYTCS",
            "lang": "it",
            "ver": "1.9.6",
            "Auth": "",
            "app-id": "",
        }
        
        async with self._session._session.get(HANDSHAKE_URL, headers=headers) as resp:
            if resp.status != 200:
                raise TecnoalarmAPIError(f"Handshake failed: {resp.status}")

            response_text = await resp.text()

        # Decode base64 response
        try:
            import json
            # Try direct JSON first
            data = json.loads(response_text)
        except json.JSONDecodeError:
            # Try base64 decode
            decoded = base64.b64decode(response_text).decode("utf-8")
            data = json.loads(decoded)

        # Extract entrypoints and token
        entrypoints = data.get("entrypoints", [])
        for ep in entrypoints:
            service_name = ep.get("serviceName", "")
            base_url = ep.get("baseUrl")
            
            if "Account" in service_name:
                self._session.account_base = base_url
            elif "TCS" in service_name:
                self._session.tcs_base = base_url
                # Store TCS service token for use in Auth header
                tcs_token = ep.get("token")
                if tcs_token:
                    self._session.token = tcs_token

        # Store app ID if present
        if "appID" in data:
            self._session.app_id = data["appID"]

    # ---------- email validation ----------

    async def validate_email(self, email: str) -> bool:
        """
        Validate if email is registered in the system.
        Returns True if email exists, False if not found.
        """
        try:
            url = self._session.account_url(f"/email/{email}")
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Auth": "",  # Required by API even if empty
            }
            async with self._session._session.get(url, headers=headers) as resp:
                if resp.status == HTTP_207_MULTI_STATUS:
                    return True
                elif resp.status == HTTP_404_NOT_FOUND:
                    raise TecnoalarmEmailNotFound(f"Email {email} not registered")
                else:
                    error_text = await resp.text()
                    raise TecnoalarmAPIError(f"Email validation failed: {resp.status} - {error_text[:200]}")
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error during email validation: {e}")

    # ---------- login ----------

    async def login(self, email: str, password: str, otp: str | None = None) -> None:
        """
        Login with email and password, optionally with OTP.
        
        Flow:
        1. First call without OTP → status 202 (OTP required, sent to email)
        2. Second call with OTP → status 200 (success, returns auth data)
        """
        payload = {
            "email": email,
            "hash": password,  # Server expects "hash" field, not "password"
        }

        # Build URL with OTP if provided
        url = self._session.account_url(ACCOUNT_LOGIN)
        if otp:
            url = f"{url}?otp={otp}"

        # Simple POST without Auth header (use token from handshake if available)
        headers = {}
        if self._session.token:
            headers["Auth"] = self._session.token

        async with self._session._session.post(url, json=payload, headers=headers) as resp:
            # First attempt without OTP → server sends OTP via email
            if resp.status == 202:
                raise TecnoalarmOTPRequired(
                    "OTP sent to email. Call login() again with otp parameter."
                )

            # Invalid credentials or expired OTP
            if resp.status == HTTP_401_UNAUTHORIZED:
                raise TecnoalarmAuthError("Invalid credentials or OTP expired")

            # Success: got auth tokens
            if resp.status != 200:
                error_text = await resp.text()
                raise TecnoalarmAPIError(f"Login failed: {resp.status} - {error_text[:200]}")

            # Response might be base64 encoded or direct JSON
            response_text = await resp.text()
            try:
                import json
                data = json.loads(response_text)
            except json.JSONDecodeError:
                # Try base64 decode
                decoded = base64.b64decode(response_text).decode("utf-8")
                data = json.loads(decoded)

        # Extract and store auth data
        # The login response contains the account/auth token
        token_from_response = data.get("token") or data.get("tcsToken") or data.get("accessToken")
        if token_from_response:
            self._session.token = str(token_from_response)
        # If no token in response, keep using the one from handshake
        self._session.account_id = data.get("accountId")
        self._session.app_id = data.get("appId") or self._session.app_id
        
        # Store central data for PIN registration (from "tp" field in response)
        if "tp" in data:
            self._central_data = data["tp"]
        elif "central" in data:
            self._central_data = data["central"]
        else:
            # Try to construct central data from available fields
            self._central_data = {
                "description": data.get("description", ""),
                "icon": data.get("icon", ""),
                "idx": data.get("idx", 0),
                "sn": data.get("sn", ""),
                "type": data.get("type", 0),
                "ip": data.get("ip"),
                "passphTCS": data.get("passphTCS", ""),
                "port": data.get("port", 0),
                "programs": data.get("programs", []),
                "remotes": data.get("remotes", []),
                "zones": data.get("zones", []),
                "codes": data.get("codes", []),
                "keys": data.get("keys", []),
                "rcmds": data.get("rcmds", []),
                "valid_data": data.get("valid_data", False),
                "syncCRC": data.get("syncCRC"),
                "use_fingerprint": data.get("use_fingerprint", True),
            }
        
        # After successful login, must register the app instance
        # This is required before accessing TCS operations
        # PUT to /tcsRC/app to register the app instance and get TCS-Token
        # Note: Server requires all TCS headers even on first call
        temp_headers = self._session.auth_headers()
        temp_headers.update({
            "TCS-Token": "disabled",  # Placeholder, server will return the real one
            "so": "IOS-26.2",
            "atype": "app",
            "lang": "it",
            "ver": "1.0",
        })
        
        async with self._session._session.put(
            self._session.tcs_url("/app"),
            json=[],
            headers=temp_headers,
        ) as resp:
            if resp.status not in (200, 201):
                error_text = await resp.text()
                raise TecnoalarmAPIError(f"App instance registration failed: {resp.status} - {error_text[:200]}")
            
            # Extract TCS-Token from response
            response_text = await resp.text()
            try:
                app_data = json.loads(response_text)
            except json.JSONDecodeError:
                # Try base64 decode
                decoded = base64.b64decode(response_text).decode("utf-8")
                app_data = json.loads(decoded)
            
            # Save TCS-Token and expiration from response
            tcs_token = app_data.get("token")
            if tcs_token:
                expiration = app_data.get("expiration")
                self._session.set_tcs_token(tcs_token, expiration)

    # ---------- app registration ----------

    async def register_app(self, pin: str | None = None) -> None:
        """
        Register the app instance with the central PIN.
        This is required after login (which already registers the app instance).
        
        If PIN is not provided, fetches it from GET /tcsRC/tps (server provides it).
        The PIN is validated by the server during registration.
        """
        def _store_program_names(programs: list | None) -> None:
            """Persist program names/description into session for later use."""
            if not programs:
                return
            mapping: dict[int, str] = {}
            for idx, prog in enumerate(programs):
                if isinstance(prog, dict):
                    name = prog.get("description") or prog.get("descr") or prog.get("name") or prog.get("label")
                    if isinstance(name, str) and name.strip():
                        mapping[idx] = name.strip()
            if mapping:
                self._session.program_names.update(mapping)

        # If PIN not provided, fetch from server via GET /tcsRC/tps
        if not pin:
            # Fetch central data from server (contains the PIN in "code" field)
            async with self._session._session.get(
                self._session.tcs_url("/tps"),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    # 401 means the token is expired or invalid - needs re-authentication
                    if resp.status == 401:
                        raise TecnoalarmReauthRequired(f"Token expired or invalid: {error_text[:200]}")
                    raise TecnoalarmAPIError(f"Failed to fetch central data: {resp.status} - {error_text[:200]}")
                
                response_text = await resp.text()
                try:
                    data = json.loads(response_text)
                except json.JSONDecodeError:
                    decoded = base64.b64decode(response_text).decode("utf-8")
                    data = json.loads(decoded)
                
                # data is likely a list of centrals
                if isinstance(data, list) and len(data) > 0:
                    central_data = data[0]
                elif isinstance(data, dict):
                    # Might be wrapped in another object
                    if "tp" in data:
                        central_data = data["tp"]
                    elif "central" in data:
                        central_data = data["central"]
                    else:
                        central_data = data
                else:
                    central_data = None
                # Capture program names from central data if present
                if isinstance(central_data, dict):
                    _store_program_names(central_data.get("programs"))
            
            # Extract PIN from central data
            if not central_data:
                raise TecnoalarmAPIError("Central data not available from GET /tps")
            
            pin = central_data.get("code") if isinstance(central_data, dict) else None
            if not pin:
                raise TecnoalarmAPIError("No PIN found in central data from GET /tps")
            
            # Store for later use
            self._central_data = central_data
        else:
            central_data = self._central_data if self._central_data else {}
            if isinstance(central_data, dict):
                _store_program_names(central_data.get("programs"))
        
        # Add PIN to central data for registration
        payload = central_data.copy() if isinstance(central_data, dict) else {}
        payload["code"] = pin
        
        async with self._session._session.post(
            self._session.tcs_url("/tp"),
            json=payload,
            headers=self._session.tcs_headers(),
        ) as resp:
            if resp.status == HTTP_412_PRECONDITION_FAILED:
                raise TecnoalarmPINRequired("Invalid PIN or PIN required")

            if resp.status != 200:
                error_text = await resp.text()
                raise TecnoalarmAPIError(f"App registration with PIN failed: {resp.status} - {error_text[:200]}")

        # Store PIN securely (will be used for future operations requiring PIN validation)
        self._session.set_pin(pin)
        
        # Store central type and ID for monitor endpoint
        if isinstance(central_data, dict):
            central_type = central_data.get("type")  # e.g., 38
            central_sn = central_data.get("sn")      # e.g., "003236056"
            
            if central_type and central_sn:
                # Convert type to model prefix using mapping
                from .constants import MODEL_PREFIX_MAP, TCS_TP_STATUS_SSE
                type_str = MODEL_PREFIX_MAP.get(central_type, f"tp{central_type:03d}")  # 38 → tp042
                self._session.central_type = type_str
                self._session.central_id = central_sn
                
                # CRITICAL: Call /tpstatus/sse?quick=true to sync data from central
                # This is a Server-Sent Events (SSE) endpoint that progressively downloads
                # programs, zones, and other data from the physical central unit.
                # Without this call, GET /program will return empty []
                print("[INFO] Syncing central data via /tpstatus/sse...")
                sse_headers = self._session.tcs_headers()
                sse_headers["Accept"] = "text/event-stream"
                
                sse_data = None
                async with self._session._session.get(
                    self._session.tcs_url(f"{TCS_TP_STATUS_SSE}?quick=true"),
                    headers=sse_headers,
                ) as resp:
                    if resp.status == 200:
                        # Read the SSE stream until completion
                        # The stream contains multiple "data:" events with progress updates
                        full_data = await resp.text()
                        print(f"[INFO] Sync completed ({len(full_data)} bytes received)")
                        
                        # Parse SSE events to extract final data
                        # The last event (progress=200) contains the complete data
                        try:
                            decoded = base64.b64decode(full_data).decode('utf-8')
                        except:
                            decoded = full_data
                        
                        # Split by "data:" to get individual events
                        events = decoded.split('\ndata:')
                        
                        # Find the last event with actual data (highest progress)
                        for event in reversed(events):
                            event = event.strip().replace('data:', '', 1).strip()
                            if event:
                                try:
                                    event_data = json.loads(event)
                                    # Check if this event has programs/zones data
                                    if event_data.get('programs') or event_data.get('zones'):
                                        sse_data = event_data
                                        programs_count = len(event_data.get('programs', []))
                                        zones_count = len(event_data.get('zones', []))
                                        print(f"[INFO] Extracted SSE data: {programs_count} programs, {zones_count} zones")
                                        break
                                except:
                                    continue
                    else:
                        print(f"[WARN] /tpstatus/sse returned {resp.status} - continuing anyway")
                
                # After SSE sync, do 6 monitor calls
                monitor_path = f"/monitor/{type_str}.{central_sn}"
                for _ in range(6):
                    async with self._session._session.get(
                        self._session.tcs_url(monitor_path),
                        headers=self._session.tcs_headers(),
                    ) as resp:
                        pass
                
                # CRITICAL: Second POST /tp after SSE sync with complete data!
                # The HAR shows this is necessary to "commit" the synced data
                # The payload MUST include the programs/zones extracted from SSE
                print("[INFO] Finalizing central registration with second POST /tp...")
                
                # Update payload with SSE data if available
                if sse_data:
                    # Merge SSE data into payload
                    payload['programs'] = sse_data.get('programs', [])
                    payload['zones'] = sse_data.get('zones', [])
                    payload['remotes'] = sse_data.get('remotes', [])
                    payload['codes'] = sse_data.get('codes', [])
                    payload['keys'] = sse_data.get('keys', [])
                    payload['rcmds'] = sse_data.get('rcmds', [])
                    # Mark as valid data
                    if sse_data.get('programs') or sse_data.get('zones'):
                        payload['valid_data'] = True
                    _store_program_names(sse_data.get('programs'))
                
                async with self._session._session.post(
                    self._session.tcs_url("/tp"),
                    json=payload,
                    headers=self._session.tcs_headers(),
                ) as resp:
                    if resp.status != 200:
                        print(f"[WARN] Second POST /tp returned {resp.status} - continuing anyway")
                
                # CRITICAL: After second POST /tp, immediately do 3 monitor calls
                # The browser does 3 consecutive monitor calls after second POST /tp
                for _ in range(3):
                    async with self._session._session.get(
                        self._session.tcs_url(monitor_path),
                        headers=self._session.tcs_headers(),
                    ) as resp:
                        pass  # Discard response, just need the calls
                
                # If TCS-Token is still not set, get it via PUT /app
                if not self._session.tcs_token:
                    print("[INFO] Getting TCS-Token via PUT /app...")
                    temp_headers = self._session.auth_headers()
                    temp_headers.update({
                        "TCS-Token": "disabled",
                        "so": "IOS-26.2",
                        "atype": "app",
                        "lang": "it",
                        "ver": "1.0",
                    })
                    
                    async with self._session._session.put(
                        self._session.tcs_url("/app"),
                        json=[],
                        headers=temp_headers,
                    ) as resp:
                        if resp.status == 200:
                            response_text = await resp.text()
                            try:
                                app_data = json.loads(response_text)
                            except json.JSONDecodeError:
                                try:
                                    decoded = base64.b64decode(response_text).decode("utf-8")
                                    app_data = json.loads(decoded)
                                except:
                                    app_data = None
                            
                            if isinstance(app_data, dict):
                                tcs_token = app_data.get("token")
                                if tcs_token:
                                    expiration = app_data.get("expiration")
                                    self._session.set_tcs_token(tcs_token, expiration)
                                    print(f"[INFO] TCS-Token obtained (expires: {self._session.get_token_expiration_str()})")
                
                # Give server time to process the sync data
                import asyncio
                await asyncio.sleep(1)

    # ---------- logout ----------

    async def refresh_tcs_token(self) -> None:
        """
        Renew TCS-Token without login (uses existing Auth-Token).
        Can be called when token is about to expire or when 401 is received.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        if not self._session.tcs_token:
            raise TecnoalarmNotInitialized("No TCS-Token to refresh")
        
        temp_headers = self._session.auth_headers()
        temp_headers.update({
            "TCS-Token": "disabled",
            "so": "IOS-26.2",
            "atype": "app",
            "lang": "it",
            "ver": "1.0",
        })
        
        try:
            async with self._session._session.put(
                self._session.tcs_url("/app"),
                json=[],
                headers=temp_headers,
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    raise TecnoalarmReauthRequired(f"Token refresh failed: {resp.status} - {error_text[:200]}")
                
                response_text = await resp.text()
                print(f"[DEBUG] Refresh response: {response_text[:200]}")
                
                if not response_text:
                    print("[WARN] Empty response from token refresh - using existing token")
                    return
                
                try:
                    app_data = json.loads(response_text)
                except json.JSONDecodeError:
                    # Response might be base64 encoded
                    try:
                        decoded = base64.b64decode(response_text).decode("utf-8")
                        app_data = json.loads(decoded)
                    except Exception as e:
                        raise TecnoalarmAPIError(f"Failed to parse refresh response: {e}")
                
                # Response might be a list instead of dict
                if isinstance(app_data, list):
                    print("[INFO] Token refresh returned array (list format) - using existing token")
                    return
                
                if not isinstance(app_data, dict):
                    raise TecnoalarmAPIError(f"Unexpected response type: {type(app_data)}")
                
                # Extract new TCS-Token from response
                tcs_token = app_data.get("token")
                if tcs_token:
                    expiration = app_data.get("expiration")
                    self._session.set_tcs_token(tcs_token, expiration)
                    print(f"[INFO] TCS-Token refreshed successfully (expires: {self._session.get_token_expiration_str()})")
                else:
                    print("[WARN] No token in refresh response - server may have used existing token")
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error during token refresh: {e}")

    async def logout(self) -> None:
        """
        Logout and unregister the app.
        """
        try:
            async with self._session._session.delete(
                self._session.tcs_url(TCS_TP_REGISTER),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status not in (200, 204):
                    raise TecnoalarmAPIError(f"Logout failed: {resp.status}")
        finally:
            # Clear all session data regardless of response
            self._session.token = None
            self._session.app_id = None
            self._session.account_id = None
            self._session._pin = None