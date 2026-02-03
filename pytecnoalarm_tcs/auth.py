import base64
import json
import asyncio
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
        
        # Monitor polling state (keepalive)
        self._polling_active = False
        self._polling_task = None

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
                    # Store central name for device naming in integrations
                    central_name = central_data.get("description") or central_data.get("name")
                    if central_name:
                        self._session.central_name = str(central_name).strip()
            
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
        
        # Step 1: First POST /tp with minimal data (valid_data=false)
        # This registers the central with just the PIN, no programs/zones yet
        payload = central_data.copy() if isinstance(central_data, dict) else {}
        payload["code"] = pin
        # Remove programs/zones/remotes from first POST - they're empty anyway
        payload["programs"] = []
        payload["zones"] = []
        payload["remotes"] = []
        payload["codes"] = []
        payload["keys"] = []
        payload["rcmds"] = []
        payload["valid_data"] = False
        
        print("[INFO] Registering central (Step 1): POST /tp with PIN and empty data...")
        async with self._session._session.post(
            self._session.tcs_url("/tp"),
            json=payload,
            headers=self._session.tcs_headers(),
        ) as resp:
            if resp.status == HTTP_412_PRECONDITION_FAILED:
                raise TecnoalarmPINRequired("Invalid PIN or PIN required")

            if resp.status != 200:
                error_text = await resp.text()
                raise TecnoalarmAPIError(f"First app registration POST /tp failed: {resp.status} - {error_text[:200]}")
        
        print("[INFO] First registration successful")

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
                
                # Step 2: Get SSE data to populate programs/zones/remotes
                # The /tpstatus/sse endpoint returns Server-Sent Events with the data
                # The HAR shows it requires ONLY Cookie auth, with Accept: text/event-stream header
                print("[INFO] Step 2: Fetching programs/zones/remotes via /tpstatus/sse...")
                
                sse_data = None
                try:
                    sse_headers = {
                        "Accept": "text/event-stream",
                        # NO Auth/TCS-Token headers for SSE - only Cookie
                    }
                    
                    async with self._session._session.get(
                        self._session.tcs_url(f"{TCS_TP_STATUS_SSE}?quick=true"),
                        headers=sse_headers,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        print(f"[DEBUG] /tpstatus/sse response status: {resp.status}")
                        if resp.status == 200:
                            # Read the SSE stream
                            # Format: data:{json}\n\ndata:{json}\n\n...
                            full_response = await resp.text()
                            
                            # Try to decode if base64
                            try:
                                decoded = base64.b64decode(full_response).decode('utf-8')
                            except:
                                decoded = full_response
                            
                            print(f"[DEBUG] SSE response length: {len(decoded)} bytes")
                            
                            # Parse SSE events - look for "data:{...}" lines
                            # Take the last complete event which should have all data
                            lines = decoded.split('\n')
                            last_data = None
                            
                            for line in reversed(lines):
                                line = line.strip()
                                if line.startswith('data:'):
                                    # Remove "data:" prefix and parse JSON
                                    json_str = line[5:].strip()
                                    if json_str:
                                        try:
                                            event_data = json.loads(json_str)
                                            # Found complete data with programs/zones
                                            if (event_data.get('programs') and len(event_data.get('programs', [])) > 0) or \
                                               (event_data.get('zones') and len(event_data.get('zones', [])) > 0):
                                                last_data = event_data
                                                break
                                        except json.JSONDecodeError:
                                            continue
                            
                            if last_data:
                                sse_data = last_data
                                programs_count = len(sse_data.get('programs', []))
                                zones_count = len(sse_data.get('zones', []))
                                remotes_count = len(sse_data.get('remotes', []))
                                print(f"[INFO] SSE data extracted: {programs_count} programs, {zones_count} zones, {remotes_count} remotes")
                            else:
                                print(f"[WARN] SSE response received but no programs/zones found")
                        else:
                            print(f"[WARN] /tpstatus/sse returned {resp.status}")
                
                except asyncio.TimeoutError:
                    print(f"[WARN] /tpstatus/sse timeout after 30s - continuing with empty data")
                except Exception as e:
                    print(f"[WARN] /tpstatus/sse error: {e} - continuing with empty data")
                
                # Step 3: Do monitor polling calls (the app does these between SSE and second POST /tp)
                monitor_path = f"/monitor/{type_str}.{central_sn}"
                print(f"[DEBUG] Doing monitor polling calls to {monitor_path}...")
                for i in range(1, 7):
                    try:
                        async with self._session._session.get(
                            self._session.tcs_url(monitor_path),
                            headers=self._session.tcs_headers(),
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as resp:
                            pass  # Discard response
                    except:
                        pass  # Ignore errors
                
                # Step 4: Second POST /tp with complete data (valid_data=true)
                # This "commits" the sync with all the programs/zones/remotes data
                print("[INFO] Step 4: Finalizing registration - POST /tp with complete data...")
                
                # Prepare final payload with SSE data
                if sse_data:
                    # Update programs/zones/remotes from SSE data
                    payload['programs'] = sse_data.get('programs', [])
                    payload['zones'] = sse_data.get('zones', [])
                    payload['remotes'] = sse_data.get('remotes', [])
                    payload['codes'] = sse_data.get('codes', [])
                    payload['keys'] = sse_data.get('keys', [])
                    payload['rcmds'] = sse_data.get('rcmds', [])
                    # Mark as valid/synced
                    payload['valid_data'] = True
                    payload['syncCRC'] = sse_data.get('syncCRC')
                    # Store program names for future reference
                    _store_program_names(sse_data.get('programs'))
                
                async with self._session._session.post(
                    self._session.tcs_url("/tp"),
                    json=payload,
                    headers=self._session.tcs_headers(),
                ) as resp:
                    if resp.status != 200:
                        print(f"[WARN] Second POST /tp returned {resp.status} - continuing anyway")
                    else:
                        print(f"[INFO] Second POST /tp successful")
                
                # Step 5: Final monitor polling calls after second POST
                print(f"[DEBUG] Doing final monitor polling calls...")
                for i in range(1, 4):
                    try:
                        async with self._session._session.get(
                            self._session.tcs_url(monitor_path),
                            headers=self._session.tcs_headers(),
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as resp:
                            pass  # Discard response
                    except:
                        pass  # Ignore errors
                
                # Step 6: Start background monitor polling (keepalive)
                # This runs continuously throughout the session lifetime
                print("[INFO] Starting background monitor polling...")
                self._polling_active = True
                self._polling_task = asyncio.create_task(
                    self._start_monitor_polling(type_str, central_sn)
                )

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

    # ---------- background monitor polling (keepalive) ----------

    async def _start_monitor_polling(self, central_type: str, central_id: str) -> None:
        """
        Background task for continuous monitor polling (keepalive).
        This runs continuously while session is active.
        
        Args:
            central_type: Type prefix (e.g., "tp042")
            central_id: Central serial number (e.g., "003236056")
        """
        monitor_path = f"/monitor/{central_type}.{central_id}"
        poll_interval = 2.5  # seconds between polls (HAR shows ~2-3 second intervals)
        
        print(f"[DEBUG] Monitor polling started for {central_type}.{central_id} (interval: {poll_interval}s)")
        
        while self._polling_active:
            try:
                async with self._session._session.get(
                    self._session.tcs_url(monitor_path),
                    headers=self._session.tcs_headers(),
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    # Response status is not critical - this is just a keepalive
                    # Server might return 200, 304 (not modified), or other status codes
                    if resp.status not in (200, 304, 204):
                        print(f"[DEBUG] Monitor polling got status {resp.status} - continuing")
            except asyncio.TimeoutError:
                # Timeout is not fatal - just continue polling
                print(f"[DEBUG] Monitor polling timeout - retrying")
            except asyncio.CancelledError:
                # Task was cancelled - normal shutdown
                break
            except Exception as e:
                # Any other error - log but continue
                print(f"[DEBUG] Monitor polling error: {e} - retrying")
            
            # Wait before next polling
            try:
                await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                break
        
        print(f"[DEBUG] Monitor polling stopped")

    async def _stop_monitor_polling(self) -> None:
        """
        Stop the background monitor polling task.
        """
        if self._polling_active:
            self._polling_active = False
            
            if self._polling_task:
                try:
                    # Give the task a moment to stop gracefully
                    await asyncio.wait_for(self._polling_task, timeout=2)
                except asyncio.TimeoutError:
                    # Force cancel if it doesn't stop
                    self._polling_task.cancel()
                    try:
                        await self._polling_task
                    except asyncio.CancelledError:
                        pass
                except Exception:
                    pass
                
                self._polling_task = None

    async def logout(self) -> None:
        """
        Logout and unregister the app.
        """
        # Stop background polling first
        await self._stop_monitor_polling()
        
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