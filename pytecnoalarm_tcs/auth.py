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
        
        # Monitor streaming state (persistent connection)
        self._monitor_stream_task: asyncio.Task | None = None
        self._monitor_response: aiohttp.ClientResponse | None = None
        
        # Legacy polling state (kept for compatibility)
        self._polling_active = False
        self._polling_task: asyncio.Task | None = None

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

        # Optional post-login warmup calls (non-blocking if they fail)
        try:
            await self._post_login_warmup()
        except Exception:
            pass

    # ---------- post-login warmup ----------

    def _tcs_headers_allow_empty_token(self) -> dict:
        headers = self._session.auth_headers()
        # IMPROVEMENT (from HAR): Official app sends "disabled" instead of empty string
        headers["TCS-Token"] = self._session.tcs_token or "disabled"
        headers.update({
            "atype": "app",
            "lang": "it",
            "ver": "1.0",
            "Accept": "application/json, text/plain, */*",
        })
        return headers

    async def get_account_short(self) -> str | None:
        """Fetch /account/short (returns base64 string, often '[]')."""
        url = self._session.account_url("/short")
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Auth": self._session.token or "",
        }
        async with self._session._session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return None
            return await resp.text()

    async def get_push_preference(self) -> str | None:
        """Fetch /tcs/app/pushPreference (base64 'true/false')."""
        url = self._session.tcs_url("/app/pushPreference")
        headers = self._tcs_headers_allow_empty_token()
        async with self._session._session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return None
            return await resp.text()

    async def get_push_count(self) -> str | None:
        """Fetch /tcs/push/count (base64 numeric string)."""
        url = self._session.tcs_url("/push/count")
        headers = self._tcs_headers_allow_empty_token()
        async with self._session._session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return None
            return await resp.text()

    async def _post_login_warmup(self) -> None:
        """Optional warmup calls seen in the official app after login."""
        await self.get_account_short()
        await self.get_push_preference()
        await self.get_push_count()

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

        # CRITICAL: Always fetch central data from GET /tcs/tps
        # This is needed to get description, icon, sn, type, passphTCS, etc.
        # for the first POST /tp request
        print("[INFO] Fetching central data from GET /tcs/tps...")
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
            
            # Store for later use
            self._central_data = central_data
        
        # Validate central data
        if not central_data:
            raise TecnoalarmAPIError("Central data not available from GET /tps")
        
        # If PIN not provided, extract it from central data
        if not pin:
            pin = central_data.get("code") if isinstance(central_data, dict) else None
            if not pin:
                raise TecnoalarmAPIError("No PIN found in central data from GET /tps")
        
        # Step 0.5: GET /monitor to obtain the syncCRC value
        # CRITICAL: The official app calls GET /monitor BEFORE the first POST /tp
        # to obtain the CRC value needed for syncCRC field
        central_type = central_data.get("type")
        central_sn = central_data.get("sn")
        
        # Build monitor URL based on type and serial number
        # Example: type=38 → tp042, sn=003236056 → /monitor/tp042.003236056
        type_map: dict[int, str] = {
            38: "tp042",  # TP042 panel
            # Add other types if needed
        }
        # Default to formatted type number if not in map or if type is None
        if central_type is not None and central_type in type_map:
            type_str = type_map[central_type]
        elif central_type is not None:
            type_str = f"tp{central_type:03d}"
        else:
            type_str = "tp000"  # Fallback if type is None
        monitor_url = f"/monitor/{type_str}.{central_sn}"
        
        print(f"[INFO] Fetching CRC from GET {monitor_url}...")
        sync_crc = None
        try:
            async with self._session._session.get(
                self._session.tcs_url(monitor_url),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status == 200:
                    body_bytes = await resp.read()
                    decoded = body_bytes.decode("utf-8")
                    monitor_data = json.loads(decoded)
                    sync_crc = monitor_data.get("crc")
                    print(f"[DEBUG] Retrieved CRC from monitor: {sync_crc}")
                else:
                    print(f"[WARN] GET {monitor_url} returned {resp.status}, CRC will be null")
        except Exception as e:
            print(f"[WARN] Failed to fetch monitor CRC: {e}, CRC will be null")
        
        # Step 1: First POST /tp with minimal data (valid_data=false)
        # This registers the central with just the PIN, no programs/zones yet
        # CRITICAL: Use actual data from GET /tcs/tps (description, icon, sn, type, etc.)
        # NOT empty values!
        payload = central_data.copy() if isinstance(central_data, dict) else {}
        
        # Ensure required fields from GET /tcs/tps are present
        # (description, icon, idx, sn, type, passphTCS, port)
        # The response from /tcs/tps already has these, but ensure code is set
        payload["code"] = pin
        
        # Clear data arrays for first POST (will be populated after SSE)
        payload["programs"] = []
        payload["zones"] = []
        payload["remotes"] = []
        payload["codes"] = []
        payload["keys"] = []
        payload["rcmds"] = []
        
        # Mark as initial registration (not yet synced)
        payload["valid_data"] = False
        payload["syncCRC"] = sync_crc  # Use CRC from GET /monitor
        payload["use_fingerprint"] = True
        
        print("[INFO] Registering central (Step 1): POST /tp with PIN and empty data...")
        print(f"[DEBUG] Payload: description={payload.get('description')}, sn={payload.get('sn')}, type={payload.get('type')}")
        
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
                
                # IMPORTANT: Both /monitor and /tpstatus/sse are STREAMING endpoints
                # They keep connections open indefinitely and send continuous data
                # They are NOT traditional request/response endpoints!
                
                # Step 2: Open the long-lived monitor stream
                # This connection will stay open throughout the entire session
                monitor_path = f"/monitor/{type_str}.{central_sn}"
                print(f"[DEBUG] Step 2: Opening persistent monitor stream to {monitor_path}...")
                
                # Headers for monitor endpoint (uses Auth header, not TCS-Token)
                monitor_headers = self._session.auth_headers()
                monitor_headers.update({
                    "Accept": "application/json, text/plain, */*",
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "cors",
                    "Origin": "ionic://evolution.tecnoalarm.com",
                    # TCS-Token can be empty for monitor endpoint
                })
                
                # Start the persistent monitor stream in background
                # This will run indefinitely and be closed at logout
                self._monitor_response = None
                self._monitor_stream_task = asyncio.create_task(
                    self._maintain_monitor_stream(monitor_path, monitor_headers)
                )
                
                # Give the stream a moment to connect
                await asyncio.sleep(0.5)
                
                # Step 3: Get SSE data to populate programs/zones/remotes
                # The /tpstatus/sse endpoint returns Server-Sent Events with the data
                # Must match exactly the headers the mobile app sends, or server returns 406
                print("[INFO] Step 3: Fetching programs/zones/remotes via /tpstatus/sse...")
                
                sse_data = None
                try:
                    # Headers MUST match exactly what mobile app sends
                    sse_headers = {
                        "Accept": "text/event-stream",
                        "Sec-Fetch-Site": "cross-site",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "it-IT,it;q=0.9",
                        "Sec-Fetch-Mode": "cors",
                        "Cache-Control": "no-cache",
                        "Origin": "ionic://evolution.tecnoalarm.com",
                        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                        "Connection": "keep-alive",
                        "Pragma": "no-cache",
                        "Sec-Fetch-Dest": "empty",
                    }
                    
                    # SSE is streaming: server keeps connection open indefinitely
                    # Parameter ?quick=true tells server to send data + complete the stream
                    # Server takes ~13 seconds to send first event
                    
                    sse_url = self._session.tcs_url(f"{TCS_TP_STATUS_SSE}?quick=true")
                    print(f"[DEBUG] SSE request to {sse_url} (expect ~13s response)...")
                    
                    async with self._session._session.get(
                        sse_url,
                        headers=sse_headers,
                        timeout=aiohttp.ClientTimeout(sock_read=30),  # 30s to get first chunk
                    ) as resp:
                        print(f"[DEBUG] SSE status: {resp.status}")
                        
                        if resp.status == 200:
                            # SSE Protocol: Server sends progress events (0→100→200)
                            # Progress events 0-100: {"description":..., "progress": N, "programs":[],"zones":[],"remotes":[],...}
                            # Final payload at progress=200: same structure but with full data
                            chunk_buffer = ""
                            
                            try:
                                # Use iter_chunked to read data as it arrives
                                async for chunk in resp.content.iter_chunked(4096):
                                    if not chunk:
                                        continue
                                    
                                    chunk_text = chunk.decode('utf-8', errors='ignore')
                                    chunk_buffer += chunk_text
                                    
                                    # Try to extract a complete SSE event: "data:{json}\n\n"
                                    if '\n\n' in chunk_buffer:
                                        events = chunk_buffer.split('\n\n')
                                        
                                        # Process complete events
                                        for event_text in events[:-1]:
                                            for line in event_text.strip().split('\n'):
                                                if not line.startswith('data:'):
                                                    continue
                                                json_str = line[5:].strip()
                                                if not json_str:
                                                    continue
                                                try:
                                                    event_data = json.loads(json_str)
                                                except json.JSONDecodeError:
                                                    continue
                                                
                                                # Track progress events
                                                progress = event_data.get('progress')
                                                if progress is not None:
                                                    print(f"[DEBUG] SSE progress: {progress}")
                                                
                                                # CRITICAL FIX (from HAR analysis):
                                                # Final payload arrives at progress=200 (not 100!)
                                                # At progress=200, programs/zones/remotes contain all actual data
                                                if progress >= 200 and isinstance(event_data, dict):
                                                    programs = event_data.get('programs', [])
                                                    # Verify we have actual data
                                                    if programs and len(programs) > 0:
                                                        sse_data = event_data
                                                        programs_count = len(sse_data.get('programs', []))
                                                        zones_count = len(sse_data.get('zones', []))
                                                        remotes_count = len(sse_data.get('remotes', []))
                                                        print(f"[INFO] SSE final payload at progress={progress}: {programs_count} programs, {zones_count} zones, {remotes_count} remotes")
                                                        break
                                        
                                        # Exit loop if we got data
                                        if sse_data:
                                            break
                                        
                                        # Keep incomplete event for next iteration
                                        chunk_buffer = events[-1]
                            
                            except asyncio.TimeoutError:
                                print(f"[WARN] SSE timeout - no response from server")
                        else:
                            print(f"[WARN] SSE returned {resp.status}")
                
                except asyncio.TimeoutError:
                    print(f"[WARN] SSE connection timeout")
                except Exception as e:
                    print(f"[WARN] SSE error: {type(e).__name__}: {e}")
                
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
                    # CONFIRMED (manual Proxyman check): 
                    # POST /tcs/tp DOES send valid_data: true
                    # (only GET /tcs/tps doesn't have it)
                    payload['valid_data'] = True
                    # Store program names for future reference
                    _store_program_names(sse_data.get('programs'))
                
                async with self._session._session.post(
                    self._session.tcs_url("/tp"),
                    json=payload,
                    headers=self._session.tcs_headers(),
                ) as resp:
                    if resp.status != 200:
                        print(f"[WARN] Second POST /tp returned {resp.status}")
                    else:
                        print(f"[INFO] Second POST /tp successful")

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

    # ---------- persistent monitor stream (replaces polling) ----------

    async def _maintain_monitor_stream(self, monitor_path: str, monitor_headers: dict) -> None:
        """
        Maintain a persistent streaming connection to the monitor endpoint.
        
        The /monitor endpoint is a SERVER-SENT EVENTS (SSE) style streaming endpoint:
        - Client connects with GET request
        - Server keeps connection OPEN INDEFINITELY
        - Server continuously sends event updates over the same connection
        - Connection stays open throughout the entire session
        
        This replaces the old polling model (separate requests).
        
        Args:
            monitor_path: Path like "/monitor/tp042.003236056"
            monitor_headers: Headers dict with Auth, Accept, etc.
        """
        monitor_url = self._session.tcs_url(monitor_path)
        
        print(f"[DEBUG] Starting persistent monitor stream to {monitor_path}...")
        
        try:
            # Open connection with NO TIMEOUT - it stays open indefinitely
            async with self._session._session.get(
                monitor_url,
                headers=monitor_headers,
                timeout=aiohttp.ClientTimeout(total=None),  # No timeout - stays open
            ) as resp:
                self._monitor_response = resp
                
                print(f"[DEBUG] Monitor stream connected (status {resp.status})")
                
                if resp.status != 200:
                    print(f"[WARN] Monitor stream returned {resp.status}")
                    return
                
                # Read data continuously as it arrives from server
                # Don't close until logout
                try:
                    async for chunk in resp.content.iter_chunked(4096):
                        if chunk:
                            # Just receive and discard - server sends updates periodically
                            # In the future, we could parse events if needed
                            pass
                except asyncio.CancelledError:
                    print(f"[DEBUG] Monitor stream cancelled")
                    raise
        
        except asyncio.CancelledError:
            print(f"[DEBUG] Monitor stream task cancelled")
        except Exception as e:
            print(f"[WARN] Monitor stream error: {type(e).__name__}: {e}")
        finally:
            self._monitor_response = None
            print(f"[DEBUG] Monitor stream closed")

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
        Stop the monitor stream and background polling tasks.
        """
        # Close persistent monitor stream
        if self._monitor_stream_task:
            try:
                self._monitor_stream_task.cancel()
                await self._monitor_stream_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._monitor_stream_task = None
        
        # Close polling task (legacy)
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