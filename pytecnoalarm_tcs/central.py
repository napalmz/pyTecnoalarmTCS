"""
Central alarm system operations.
Handles programs, zones, remotes, logs, and monitoring.
"""
import base64
import json
import asyncio
import time
import aiohttp
from typing import Any, Optional
from dataclasses import dataclass

from .exceptions import (
    TecnoalarmNotInitialized,
    TecnoalarmPINRequired,
    TecnoalarmAPIError,
)
from .constants import (
    TCS_MONITOR,
    TCS_TPS,
    TCS_PROGRAM,
    TCS_PROGRAM_ARM,
    TCS_ZONE,
    TCS_REMOTE,
    TCS_LOG,
    TCS_LOG_MEMORY_DELETE,
    TCS_PUSH,
    TCS_PUSH_COUNT,
    PROGRAM_STATUS,
    ZONE_STATUS,
)


@dataclass
class Program:
    """
    Program (armed state) data.
    
    Status values:
    - 0 = disarmed (OFF)
    - 1 = armed_day (optional, advanced systems)
    - 2 = armed_night (optional, advanced systems)
    - 3 = armed (ON - standard arm mode)
    """
    index: int
    name: str | None
    status: int  # 0=disarmed, 1=day, 2=night, 3=away
    prealarm: bool
    alarm: bool
    memory_alarm: bool
    free: bool

    @property
    def status_name(self) -> str:
        """Get human-readable status name"""
        return PROGRAM_STATUS.get(self.status, "unknown")

    @property
    def display_name(self) -> str:
        """Get program display name (custom name or default)"""
        return self.name or f"Program {self.index}"
    
    @property
    def is_armed(self) -> bool:
        """Check if program is armed (any armed mode)"""
        return self.status != 0
    
    @property
    def is_disarmed(self) -> bool:
        """Check if program is disarmed"""
        return self.status == 0


@dataclass
class Zone:
    """Zone sensor data"""
    index: int
    description: str
    icon: int
    status: int
    camera: bool
    allocated: bool
    in_supervision: bool
    in_low_battery: bool
    in_fail: bool
    in_paired_device_supervision: bool


@dataclass
class LogEntry:
    """Log entry with timestamp and event details"""
    evento: int  # Event code
    indice1: int
    indice2: int
    indice3: int
    descr: str  # Event description
    date: str  # Date in DD/MM/YY format
    time: str  # Time in HH:MM:SS format
    category: int
    visibility: int
    clip_path: str = ""
    has_clip: bool = False
    
    @property
    def timestamp(self) -> str:
        """Combined date and time"""
        return f"{self.date} {self.time}"
    
    @property
    def description(self) -> str:
        """Event description"""
        return self.descr


class TecnoalarmCentral:
    def __init__(self, session):
        self._session = session
        self._session_activation_lock = asyncio.Lock()
        self._last_zone_activation = 0.0  # Time of last zone session activation
        self._zone_activation_interval = 1.0  # Minimum seconds between zone activations (increased from 2s)
        
        # Streaming connections for /program, /zone, /remote, /monitor endpoints
        self._program_stream_task: asyncio.Task | None = None
        self._zone_stream_task: asyncio.Task | None = None
        self._remote_stream_task: asyncio.Task | None = None
        self._monitor_stream_task: asyncio.Task | None = None
        
        # Cached data from streaming endpoints
        self._cached_programs: list[Program] = []
        self._cached_zones: list[Zone] = []
        self._cached_remotes: list[dict] = []
        self._cached_monitor: dict[str, Any] = {}
        
        # Lock for cache access
        self._cache_lock = asyncio.Lock()
        
        # Streaming configuration
        self._stream_reconnect_interval = 540  # 9 minutes (540 seconds) for program/zone/remote
        self._monitor_reconnect_interval = 540  # 9 minutes (540 seconds) for monitor

    # ---------- Central Info ----------

    async def get_central_status(self) -> dict[str, Any]:
        """
        Get current central status including programs, zones, remotes.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        programs = await self.get_programs()
        zones = await self.get_zones()
        remotes = await self.get_remotes()

        return {
            "programs": programs,
            "zones": zones,
            "remotes": remotes,
        }

    async def get_central_list(self) -> dict[str, Any]:
        """
        Get list of all centrals associated with account.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.get(
                self._session.tcs_url(TCS_TPS),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(f"Get central list failed: {resp.status}")

                data = await resp.json()
                # Could be base64 encoded
                if isinstance(data, str):
                    data = json.loads(
                        base64.b64decode(data).decode("utf-8")
                    )

                return data
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting central list: {e}")

    async def monitor_central(self, tp_type: str, central_id: str) -> dict[str, Any]:
        """
        Monitor central status by polling /monitor/{tp_type}.{central_id}.
        This returns the current state of programs, zones, etc.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        path = TCS_MONITOR.format(tp_type=tp_type, central_id=central_id)

        try:
            async with self._session._session.get(
                self._session.tcs_url(path),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(f"Monitor central failed: {resp.status}")

                data = await resp.json()
                if isinstance(data, str):
                    data = json.loads(
                        base64.b64decode(data).decode("utf-8")
                    )

                # Extract central type and ID for future use
                self._session.central_type = tp_type
                self._session.central_id = central_id

                return data
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error monitoring central: {e}")

    # ---------- Programs ----------

    async def _activate_central_session(self) -> None:
        """
        Activate the central in the server session by calling monitor endpoint.
        This refreshes the server-side session state and MUST be called before
        any GET /program, /zone, /remote, /log requests.
        The browser app does continuous polling of monitor while the session is active.
        
        This method is protected by a lock to prevent concurrent activation attempts
        that could cause race conditions in session state.
        """
        async with self._session_activation_lock:
            if not self._session.central_type or not self._session.central_id:
                return  # No central selected
            
            monitor_path = f"/monitor/{self._session.central_type}.{self._session.central_id}"
            
            # Call monitor once to refresh server-side session state
            # (Reduced from 3 calls to avoid 503 errors from excessive requests)
            try:
                async with self._session._session.get(
                    self._session.tcs_url(monitor_path),
                    headers=self._session.tcs_headers(),
                ) as resp:
                    if resp.status != 200:
                        # Log warning but continue - monitor failures are non-fatal
                        pass
            except Exception as e:
                # Network errors on monitor are non-fatal, continue
                pass
    
    async def _maintain_program_stream(self) -> None:
        """
        Maintain a persistent streaming connection to GET /tcs/program.
        
        The /tcs/program endpoint uses chunked transfer encoding and keeps
        the connection open, sending periodic updates. This method:
        - Opens a long-lived connection
        - Reads chunks as they arrive
        - Updates the cached programs list
        - Reconnects every 9 minutes (540 seconds)
        """
        import sys
        
        while True:
            print("[DEBUG] Starting program stream connection...", file=sys.stderr)
            
            try:
                # Activate session first
                await self._activate_central_session()
                
                # Open streaming connection with long timeout
                # Use sock_read instead of total to allow long idle periods between chunks
                async with self._session._session.get(
                    self._session.tcs_url(TCS_PROGRAM),
                    headers=self._session.tcs_headers(),
                    timeout=aiohttp.ClientTimeout(total=None, sock_read=self._stream_reconnect_interval + 60),
                ) as resp:
                    if resp.status != 200:
                        print(f"[ERROR] Program stream failed: {resp.status}", file=sys.stderr)
                        await asyncio.sleep(10)  # Wait before retry
                        continue
                    
                    print(f"[DEBUG] Program stream connected (status {resp.status})", file=sys.stderr)
                    
                    # Read chunks with timeout for reconnection
                    stream_start = asyncio.get_event_loop().time()
                    
                    async for chunk in resp.content.iter_chunked(4096):
                        if not chunk:
                            continue
                        
                        # Decode and parse the chunk
                        try:
                            chunk_text = chunk.decode('utf-8').strip()
                            
                            # Try parsing as JSON first (might not be base64)
                            try:
                                data = json.loads(chunk_text)
                            except json.JSONDecodeError:
                                # Try base64 decoding
                                decoded = base64.b64decode(chunk_text).decode('utf-8')
                                data = json.loads(decoded)
                            
                            if isinstance(data, list):
                                # Update cached programs
                                programs = []
                                for idx, prog in enumerate(data):
                                    if isinstance(prog, dict):
                                        program_name = None
                                        if hasattr(self._session, "program_names"):
                                            program_name = self._session.program_names.get(idx)
                                        programs.append(
                                            Program(
                                                index=idx,
                                                name=program_name,
                                                status=prog.get("status", 0),
                                                prealarm=prog.get("prealarm", False),
                                                alarm=prog.get("alarm", False),
                                                memory_alarm=prog.get("memAlarm", False),
                                                free=prog.get("free", False),
                                            )
                                        )
                                
                                async with self._cache_lock:
                                    self._cached_programs = programs
                                    print(f"[DEBUG] Updated programs cache: {len(programs)} programs", file=sys.stderr)
                        
                        except Exception as e:
                            print(f"[WARN] Failed to parse program chunk: {e}", file=sys.stderr)
                        
                        # Check if we should reconnect
                        elapsed = asyncio.get_event_loop().time() - stream_start
                        if elapsed >= self._stream_reconnect_interval:
                            print(f"[DEBUG] Program stream reconnecting after {elapsed:.1f}s", file=sys.stderr)
                            break
                    
                    # If stream ended early, wait before reconnecting
                    elapsed = asyncio.get_event_loop().time() - stream_start
                    if elapsed < self._stream_reconnect_interval:
                        remaining = self._stream_reconnect_interval - elapsed
                        print(f"[DEBUG] Program stream ended early, waiting {remaining:.0f}s before reconnect", file=sys.stderr)
                        await asyncio.sleep(remaining)
            
            except asyncio.CancelledError:
                print("[DEBUG] Program stream cancelled", file=sys.stderr)
                break
            except Exception as e:
                print(f"[ERROR] Program stream error: {type(e).__name__}: {e}", file=sys.stderr)
                await asyncio.sleep(10)  # Wait before retry
    
    async def _maintain_zone_stream(self) -> None:
        """Maintain persistent streaming connection to GET /tcs/zone."""
        import sys
        
        while True:
            print("[DEBUG] Starting zone stream connection...", file=sys.stderr)
            
            try:
                await self._activate_central_session()
                
                async with self._session._session.get(
                    self._session.tcs_url(TCS_ZONE),
                    headers=self._session.tcs_headers(),
                    timeout=aiohttp.ClientTimeout(total=None, sock_read=self._stream_reconnect_interval + 60),
                ) as resp:
                    if resp.status != 200:
                        print(f"[ERROR] Zone stream failed: {resp.status}", file=sys.stderr)
                        await asyncio.sleep(10)
                        continue
                    
                    print(f"[DEBUG] Zone stream active (reconnecting every {self._stream_reconnect_interval}s)", file=sys.stderr)
                    
                    stream_start = asyncio.get_event_loop().time()
                    chunk_count = 0
                    buffer = ""  # Accumulate partial chunks
                    
                    async for chunk in resp.content.iter_chunked(4096):
                        if not chunk:
                            continue
                        
                        try:
                            # Decode chunk and add to buffer
                            chunk_text = chunk.decode('utf-8', errors='ignore').strip()
                            buffer += chunk_text
                            
                            # Try to parse the complete buffer
                            data = None
                            try:
                                # Try direct JSON parse first
                                data = json.loads(buffer)
                                buffer = ""  # Clear buffer on success
                            except json.JSONDecodeError:
                                # Try base64 decoding
                                try:
                                    decoded = base64.b64decode(buffer).decode('utf-8')
                                    data = json.loads(decoded)
                                    buffer = ""  # Clear buffer on success
                                except Exception:
                                    # If buffer gets too large, reset it
                                    if len(buffer) > 10000:
                                        print(f"[WARN] Zone buffer too large ({len(buffer)} chars), resetting", file=sys.stderr)
                                        buffer = ""
                                    continue  # Wait for more data
                            
                            if data and isinstance(data, list):
                                zones = []
                                for idx, zone in enumerate(data):
                                    zones.append(
                                        Zone(
                                            index=zone.get("idx", idx),
                                            description=zone.get("description", ""),
                                            icon=zone.get("icon", ""),
                                            status=zone.get("status", "UNKNOWN"),
                                            camera=zone.get("camera", ""),
                                            allocated=zone.get("allocated", False),
                                            in_supervision=zone.get("inSupervision", False),
                                            in_low_battery=zone.get("inLowBattery", False),
                                            in_fail=zone.get("inFail", False),
                                            in_paired_device_supervision=zone.get("inPairedDeviceSupervision", False),
                                        )
                                    )
                                
                                async with self._cache_lock:
                                    self._cached_zones = zones
                                
                                chunk_count += 1
                                if chunk_count == 1:
                                    print(f"[DEBUG] Received initial zone data: {len(zones)} zones", file=sys.stderr)
                        
                        except Exception as e:
                            print(f"[WARN] Failed to parse zone chunk: {e}", file=sys.stderr)
                        
                        elapsed = asyncio.get_event_loop().time() - stream_start
                        if elapsed >= self._stream_reconnect_interval:
                            print(f"[DEBUG] Zone stream reconnecting after {elapsed:.0f}s", file=sys.stderr)
                            break
                    
                    # If stream ended early, wait before reconnecting
                    elapsed = asyncio.get_event_loop().time() - stream_start
                    if elapsed < self._stream_reconnect_interval:
                        remaining = self._stream_reconnect_interval - elapsed
                        print(f"[DEBUG] Zone stream ended early, waiting {remaining:.0f}s before reconnect", file=sys.stderr)
                        await asyncio.sleep(remaining)
            
            except asyncio.CancelledError:
                print("[INFO] Zone stream stopped", file=sys.stderr)
                break
            except Exception as e:
                print(f"[ERROR] Zone stream error: {type(e).__name__}: {e}", file=sys.stderr)
                await asyncio.sleep(10)
    
    async def _maintain_remote_stream(self) -> None:
        """Maintain persistent streaming connection to GET /tcs/remote."""
        import sys
        
        while True:
            print("[DEBUG] Starting remote stream connection...", file=sys.stderr)
            
            try:
                await self._activate_central_session()
                
                async with self._session._session.get(
                    self._session.tcs_url(TCS_REMOTE),
                    headers=self._session.tcs_headers(),
                    timeout=aiohttp.ClientTimeout(total=None, sock_read=self._stream_reconnect_interval + 60),
                ) as resp:
                    if resp.status != 200:
                        print(f"[ERROR] Remote stream failed: {resp.status}", file=sys.stderr)
                        await asyncio.sleep(10)
                        continue
                    
                    print(f"[DEBUG] Remote stream active (reconnecting every {self._stream_reconnect_interval}s)", file=sys.stderr)
                    
                    stream_start = asyncio.get_event_loop().time()
                    chunk_count = 0
                    
                    async for chunk in resp.content.iter_chunked(4096):
                        if not chunk:
                            continue
                        
                        try:
                            chunk_text = chunk.decode('utf-8').strip()
                            
                            try:
                                data = json.loads(chunk_text)
                            except json.JSONDecodeError:
                                decoded = base64.b64decode(chunk_text).decode('utf-8')
                                data = json.loads(decoded)
                            
                            if isinstance(data, list):
                                async with self._cache_lock:
                                    self._cached_remotes = data
                                
                                chunk_count += 1
                                if chunk_count == 1:
                                    print(f"[DEBUG] Received initial remote data: {len(data)} remotes", file=sys.stderr)
                        
                        except Exception as e:
                            print(f"[WARN] Failed to parse remote chunk: {e}", file=sys.stderr)
                        
                        elapsed = asyncio.get_event_loop().time() - stream_start
                        if elapsed >= self._stream_reconnect_interval:
                            print(f"[DEBUG] Remote stream reconnecting after {elapsed:.0f}s", file=sys.stderr)
                            break
                    
                    # If stream ended early, wait before reconnecting
                    elapsed = asyncio.get_event_loop().time() - stream_start
                    if elapsed < self._stream_reconnect_interval:
                        remaining = self._stream_reconnect_interval - elapsed
                        print(f"[DEBUG] Remote stream ended early, waiting {remaining:.0f}s before reconnect", file=sys.stderr)
                        await asyncio.sleep(remaining)
            
            except asyncio.CancelledError:
                print("[INFO] Remote stream stopped", file=sys.stderr)
                break
            except Exception as e:
                print(f"[ERROR] Remote stream error: {type(e).__name__}: {e}", file=sys.stderr)
                await asyncio.sleep(10)
    
    async def _maintain_monitor_stream(self) -> None:
        """
        Maintain persistent streaming connection to GET /tcs/monitor.
        This is an SSE stream like /program, /zone, /remote.
        """
        import sys
        
        if not self._session.central_type or not self._session.central_id:
            print("[WARN] Cannot start monitor stream: central not configured", file=sys.stderr)
            return
        
        monitor_path = TCS_MONITOR.format(
            tp_type=self._session.central_type,
            central_id=self._session.central_id
        )
        
        while True:
            print("[DEBUG] Starting monitor stream connection...", file=sys.stderr)
            
            try:
                async with self._session._session.get(
                    self._session.tcs_url(monitor_path),
                    headers=self._session.tcs_headers(),
                    timeout=aiohttp.ClientTimeout(total=None, sock_read=self._monitor_reconnect_interval + 60),
                ) as resp:
                    if resp.status != 200:
                        print(f"[ERROR] Monitor stream failed: {resp.status}", file=sys.stderr)
                        await asyncio.sleep(10)
                        continue
                    
                    print(f"[DEBUG] Monitor stream active (reconnecting every {self._monitor_reconnect_interval}s)", file=sys.stderr)
                    
                    stream_start = asyncio.get_event_loop().time()
                    chunk_count = 0
                    
                    async for chunk in resp.content.iter_chunked(4096):
                        if not chunk:
                            continue
                        
                        try:
                            chunk_text = chunk.decode('utf-8').strip()
                            
                            try:
                                data = json.loads(chunk_text)
                            except json.JSONDecodeError:
                                decoded = base64.b64decode(chunk_text).decode('utf-8')
                                data = json.loads(decoded)
                            
                            if isinstance(data, dict):
                                async with self._cache_lock:
                                    self._cached_monitor = data
                                
                                chunk_count += 1
                                if chunk_count == 1:
                                    print(f"[DEBUG] Received initial monitor data", file=sys.stderr)
                        
                        except Exception as e:
                            print(f"[WARN] Failed to parse monitor chunk: {e}", file=sys.stderr)
                        
                        elapsed = asyncio.get_event_loop().time() - stream_start
                        if elapsed >= self._monitor_reconnect_interval:
                            print(f"[DEBUG] Monitor stream reconnecting after {elapsed:.0f}s", file=sys.stderr)
                            break
                    
                    # If stream ended early, wait before reconnecting
                    elapsed = asyncio.get_event_loop().time() - stream_start
                    if elapsed < self._monitor_reconnect_interval:
                        remaining = self._monitor_reconnect_interval - elapsed
                        print(f"[DEBUG] Monitor stream ended early, waiting {remaining:.0f}s before reconnect", file=sys.stderr)
                        await asyncio.sleep(remaining)
            
            except asyncio.CancelledError:
                print("[INFO] Monitor stream stopped", file=sys.stderr)
                break
            except Exception as e:
                print(f"[ERROR] Monitor stream error: {type(e).__name__}: {e}", file=sys.stderr)
                await asyncio.sleep(10)
    
    async def wait_for_streaming_ready(self, timeout: float = 10.0) -> bool:
        """
        Wait for streaming connections to receive initial data.
        
        Args:
            timeout: Maximum seconds to wait (default: 10)
            
        Returns:
            True if all streams have data, False if timeout
        """
        import sys
        start_time = asyncio.get_event_loop().time()
        
        while asyncio.get_event_loop().time() - start_time < timeout:
            async with self._cache_lock:
                has_programs = len(self._cached_programs) > 0
                has_zones = len(self._cached_zones) > 0
                has_remotes = len(self._cached_remotes) > 0
                
                if has_programs and has_zones:
                    print(f"[INFO] Streaming ready: {len(self._cached_programs)} programs, {len(self._cached_zones)} zones, {len(self._cached_remotes)} remotes", file=sys.stderr)
                    return True
            
            await asyncio.sleep(0.2)
        
        print(f"[WARN] Streaming timeout after {timeout}s", file=sys.stderr)
        return False
    
    async def start_streaming(self) -> None:
        """
        Start background streaming tasks for programs, zones, remotes, and monitor.
        This should be called after successful central registration.
        """
        import sys
        
        if not self._session.is_central_ready:
            print("[WARN] Cannot start streaming: central not ready", file=sys.stderr)
            return
        
        # Start program stream
        if self._program_stream_task is None or self._program_stream_task.done():
            self._program_stream_task = asyncio.create_task(self._maintain_program_stream())
            print("[INFO] Program streaming started (auto-reconnect every 9 min)", file=sys.stderr)
        
        # Start zone stream
        if self._zone_stream_task is None or self._zone_stream_task.done():
            self._zone_stream_task = asyncio.create_task(self._maintain_zone_stream())
            print("[INFO] Zone streaming started (auto-reconnect every 9 min)", file=sys.stderr)
        
        # Start remote stream
        if self._remote_stream_task is None or self._remote_stream_task.done():
            self._remote_stream_task = asyncio.create_task(self._maintain_remote_stream())
            print("[INFO] Remote streaming started (auto-reconnect every 9 min)", file=sys.stderr)
        
        # Start monitor stream
        if self._monitor_stream_task is None or self._monitor_stream_task.done():
            self._monitor_stream_task = asyncio.create_task(self._maintain_monitor_stream())
            print("[INFO] Monitor streaming started (auto-reconnect every 540 sec)", file=sys.stderr)
    
    async def stop_streaming(self) -> None:
        """
        Stop all background streaming tasks.
        This should be called during logout.
        """
        import sys
        
        # Stop all streaming tasks
        tasks = [
            (self._program_stream_task, "Program"),
            (self._zone_stream_task, "Zone"),
            (self._remote_stream_task, "Remote"),
            (self._monitor_stream_task, "Monitor"),
        ]
        
        for task, name in tasks:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                print(f"[INFO] {name} streaming stopped", file=sys.stderr)
    
    async def get_programs(self) -> list[Program]:
        """
        Get list of programs (armed states).
        
        This method returns cached data from the persistent streaming connection.
        If streaming is not active, it will start it and wait for initial data.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        # Start streaming if not already running (check ALL tasks, not just program)
        all_tasks_running = (
            (self._program_stream_task and not self._program_stream_task.done()) and
            (self._zone_stream_task and not self._zone_stream_task.done()) and
            (self._remote_stream_task and not self._remote_stream_task.done()) and
            (self._monitor_stream_task and not self._monitor_stream_task.done())
        )
        
        if not all_tasks_running:
            await self.start_streaming()
            
            # Wait for initial data (up to 10 seconds)
            for i in range(100):  # 100 * 0.1s = 10 seconds max
                await asyncio.sleep(0.1)
                async with self._cache_lock:
                    if self._cached_programs:
                        break
        
        # Return cached data
        async with self._cache_lock:
            return self._cached_programs.copy()

    async def arm_program(self, program_idx: int, mode: int, pin: str | None = None) -> bool:
        """
        Arm a specific program with the specified mode.
        
        Args:
            program_idx: Program index (0-3)
            mode: Arm mode - 1=day, 2=night, 3=away
            pin: PIN for security validation (required)
        
        Returns:
            True if successful
        
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmPINRequired: If PIN is missing or incorrect
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        # Validate PIN
        if not pin:
            raise TecnoalarmPINRequired("PIN is required for arm operation")
        
        stored_pin = self._session.get_pin()
        if not stored_pin or stored_pin != pin:
            raise TecnoalarmPINRequired("Invalid PIN")

        if mode not in [1, 2, 3]:
            raise ValueError(f"Invalid arm mode: {mode}. Must be 1 (day), 2 (night), or 3 (away)")

        mode_name = {1: "day", 2: "night", 3: "away"}[mode]
        
        try:
            # The endpoint pattern from HAR: PUT /tcsRC/program/{idx}/on
            # We construct the mode endpoint dynamically
            path = f"/program/{program_idx}/on"
            
            async with self._session._session.put(
                self._session.tcs_url(path),
                headers=self._session.tcs_headers(),
                json={"mode": mode}  # Send the mode in the body
            ) as resp:
                if resp.status not in [200, 201]:
                    raise TecnoalarmAPIError(f"Arm program {program_idx} failed: {resp.status}")
                
                return True
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error arming program {program_idx}: {e}")

    async def disarm_program(self, program_idx: int, pin: str | None = None) -> bool:
        """
        Disarm a specific program.
        
        Args:
            program_idx: Program index (0-3)
            pin: PIN for security validation (required)
        
        Returns:
            True if successful
        
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmPINRequired: If PIN is missing or incorrect
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        # Validate PIN
        if not pin:
            raise TecnoalarmPINRequired("PIN is required for disarm operation")
        
        stored_pin = self._session.get_pin()
        if not stored_pin or stored_pin != pin:
            raise TecnoalarmPINRequired("Invalid PIN")

        try:
            # The endpoint pattern from HAR: PUT /tcsRC/program/{idx}/off
            path = f"/program/{program_idx}/off"
            
            async with self._session._session.put(
                self._session.tcs_url(path),
                headers=self._session.tcs_headers(),
                json={}  # Empty body for disarm
            ) as resp:
                if resp.status not in [200, 201]:
                    raise TecnoalarmAPIError(f"Disarm program {program_idx} failed: {resp.status}")
                
                return True
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error disarming program {program_idx}: {e}")

    # ---------- Zones ----------

    async def get_zones(self) -> list[Zone]:
        """
        Get list of zones with their current status.
        
        This method returns cached data from the persistent streaming connection.
        If streaming is not active, it will start it and wait for initial data.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        # Start streaming if not already running (check all tasks)
        all_tasks_running = (
            (self._program_stream_task and not self._program_stream_task.done()) and
            (self._zone_stream_task and not self._zone_stream_task.done()) and
            (self._remote_stream_task and not self._remote_stream_task.done()) and
            (self._monitor_stream_task and not self._monitor_stream_task.done())
        )
        
        if not all_tasks_running:
            await self.start_streaming()
            
            # Wait for initial data (up to 10 seconds)
            for i in range(100):  # 100 * 0.1s = 10 seconds max
                await asyncio.sleep(0.1)
                async with self._cache_lock:
                    if self._cached_zones:
                        break
        
        # Return cached data
        async with self._cache_lock:
            return self._cached_zones.copy()

        try:
            # Rate limit zone activation to avoid overwhelming server
            # Only activate if 1+ second has passed since last zone activation
            now = time.time()
            if now - self._last_zone_activation >= self._zone_activation_interval:
                await self._activate_central_session()
                self._last_zone_activation = now
            
            async with self._session._session.get(
                self._session.tcs_url(TCS_ZONE),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    # If zones fail with 404, it means session is completely dead
                    # Force a full reactivation for the next call
                    if resp.status == 404:
                        self._last_zone_activation = 0.0
                    raise TecnoalarmAPIError(f"Get zones failed: {resp.status}")

                response_data = await resp.text()
                
                # Handle empty response
                if not response_data:
                    import sys
                    print("[WARN] GET /zone returned empty response", file=sys.stderr)
                    return []
                
                try:
                    # Try parsing as JSON first
                    data = json.loads(response_data)
                except json.JSONDecodeError:
                    # Response is base64 encoded JSON array
                    try:
                        decoded = base64.b64decode(response_data).decode("utf-8")
                        data = json.loads(decoded)
                    except Exception as decode_err:
                        import sys
                        print(f"[ERROR] Failed to decode zones response: {decode_err}", file=sys.stderr)
                        return []

                zones = []
                if isinstance(data, list):
                    for idx, zone in enumerate(data):
                        zones.append(
                            Zone(
                                index=zone.get("idx", idx),
                                description=zone.get("description", ""),
                                icon=zone.get("icon", ""),
                                status=zone.get("status", "UNKNOWN"),
                                camera=zone.get("camera", ""),
                                allocated=zone.get("allocated", False),
                                in_supervision=zone.get("inSupervision", False),
                                in_low_battery=zone.get("inLowBattery", False),
                                in_fail=zone.get("inFail", False),
                                in_paired_device_supervision=zone.get(
                                    "inPairedDeviceSupervision", False
                                ),
                            )
                        )
                else:
                    import sys
                    print(f"[ERROR] GET /zone response is not a list, got {type(data).__name__}: {str(data)[:200]}", file=sys.stderr)

                return zones
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting zones: {e}")

    # ---------- Remotes ----------

    async def get_remotes(self) -> list:
        """
        Get list of remotes (wireless key fobs) and their battery status.
        
        This method returns cached data from the persistent streaming connection.
        If streaming is not active, it will start it and wait for initial data.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        
        # Start streaming if not already running (check all tasks)
        all_tasks_running = (
            (self._program_stream_task and not self._program_stream_task.done()) and
            (self._zone_stream_task and not self._zone_stream_task.done()) and
            (self._remote_stream_task and not self._remote_stream_task.done()) and
            (self._monitor_stream_task and not self._monitor_stream_task.done())
        )
        
        if not all_tasks_running:
            await self.start_streaming()
            
            # Wait for initial data (up to 10 seconds)
            for i in range(100):  # 100 * 0.1s = 10 seconds max
                await asyncio.sleep(0.1)
                async with self._cache_lock:
                    if self._cached_remotes:
                        break
        
        # Return cached data
        async with self._cache_lock:
            return self._cached_remotes.copy()

        try:
            # Activate central session FIRST
            await self._activate_central_session()
            
            async with self._session._session.get(
                self._session.tcs_url(TCS_REMOTE),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(f"Get remotes failed: {resp.status}")

                response_data = await resp.text()
                
                # Handle empty response
                if not response_data:
                    import sys
                    print("[WARN] GET /remote returned empty response", file=sys.stderr)
                    return []
                
                try:
                    # Try parsing as JSON first
                    data = json.loads(response_data)
                except json.JSONDecodeError:
                    # Response is base64 encoded JSON array
                    try:
                        decoded = base64.b64decode(response_data).decode("utf-8")
                        data = json.loads(decoded)
                    except Exception as decode_err:
                        import sys
                        print(f"[ERROR] Failed to decode remotes response: {decode_err}", file=sys.stderr)
                        return []

                if isinstance(data, list):
                    return data
                else:
                    import sys
                    print(f"[ERROR] GET /remote response is not a list, got {type(data).__name__}: {str(data)[:200]}", file=sys.stderr)
                    return []
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting remotes: {e}")

    # ---------- Logs ----------

    async def get_logs(self, from_id: int = 0, limit: int = 100) -> list[LogEntry]:
        """
        Get alarm system logs starting from given ID.
        Returns a list of LogEntry objects with event details.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        path = TCS_LOG.format(from_id=from_id)

        try:
            # Activate central session FIRST
            await self._activate_central_session()
            
            async with self._session._session.get(
                self._session.tcs_url(path),
                headers=self._session.tcs_headers(),
                params={"take": limit},
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(f"Get logs failed: {resp.status}")

                response_data = await resp.text()
                
                # Handle empty response
                if not response_data:
                    return []
                
                try:
                    # Try parsing as JSON first
                    data = json.loads(response_data)
                except json.JSONDecodeError:
                    # Response is base64 encoded JSON
                    try:
                        decoded = base64.b64decode(response_data).decode("utf-8")
                        data = json.loads(decoded)
                    except Exception:
                        return []

                # Parse log entries
                logs = []
                if isinstance(data, list):
                    for log in data:
                        if isinstance(log, dict):
                            logs.append(
                                LogEntry(
                                    evento=log.get("evento", 0),
                                    indice1=log.get("indice1", 0),
                                    indice2=log.get("indice2", 0),
                                    indice3=log.get("indice3", 0),
                                    descr=log.get("descr", ""),
                                    date=log.get("date", ""),
                                    time=log.get("time", ""),
                                    category=log.get("category", 0),
                                    visibility=log.get("visibility", 0),
                                    clip_path=log.get("clipPath", ""),
                                    has_clip=log.get("clip", False),
                                )
                            )
                
                return logs
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting logs: {e}")

    async def clear_alarm_memory(self) -> None:
        """
        Clear the alarm system's memory of past alarms.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.delete(
                self._session.tcs_url(TCS_LOG_MEMORY_DELETE),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status not in (200, 204):
                    raise TecnoalarmAPIError(
                        f"Clear alarm memory failed: {resp.status}"
                    )
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error clearing alarm memory: {e}")

    # ---------- Push Notifications ----------

    async def get_push_notification_count(self) -> int:
        """
        Get count of unread push notifications.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.get(
                self._session.tcs_url(TCS_PUSH_COUNT),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(
                        f"Get push notification count failed: {resp.status}"
                    )

                data = await resp.json()
                if isinstance(data, dict):
                    return data.get("count", 0)
                return data
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting push count: {e}")

    async def get_push_notifications(self, take: int = 10) -> list[dict]:
        """
        Get list of push notifications.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.get(
                self._session.tcs_url(TCS_PUSH),
                headers=self._session.tcs_headers(),
                params={"take": take},
            ) as resp:
                if resp.status != 200:
                    raise TecnoalarmAPIError(
                        f"Get push notifications failed: {resp.status}"
                    )

                data = await resp.json()
                if isinstance(data, str):
                    data = json.loads(
                        base64.b64decode(data).decode("utf-8")
                    )

                return data
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error getting push notifications: {e}")

    async def mark_all_push_as_read(self) -> bool:
        """
        Mark all push notifications as read (mark as letti).
        
        Returns:
            True if successful
            
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.put(
                self._session.tcs_url("/push/all"),
                headers=self._session.tcs_headers(),
            ) as resp:
                if resp.status not in [200, 204]:
                    raise TecnoalarmAPIError(
                        f"Mark all push as read failed: {resp.status}"
                    )
                return True
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error marking push as read: {e}")

    async def mark_push_notifications_as_read(self, notifications: list[dict]) -> bool:
        """
        Mark specific push notifications as read by resending them with readStatus=true.
        This is what the app does when you view the notifications list.

        Args:
            notifications: List of notification dicts from get_push_notifications()

        Returns:
            True if successful

        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        if not notifications:
            return True

        # Mark all notifications as read
        for notif in notifications:
            notif["readStatus"] = True
            if "selected" not in notif:
                notif["selected"] = True

        try:
            async with self._session._session.put(
                self._session.tcs_url("/push"),
                headers=self._session.tcs_headers(),
                json=notifications,
            ) as resp:
                if resp.status not in [200, 204]:
                    raise TecnoalarmAPIError(
                        f"Mark push notifications as read failed: {resp.status}"
                    )
                return True
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error marking push as read: {e}")

    async def delete_push_notification(self, notification_id: int) -> bool:
        """
        Delete (cancel/remove) a specific push notification.
        
        Args:
            notification_id: ID of the notification to delete
            
        Returns:
            True if successful
            
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        try:
            async with self._session._session.delete(
                self._session.tcs_url("/push"),
                headers=self._session.tcs_headers(),
                params={"ids": notification_id}
            ) as resp:
                if resp.status not in [200, 204]:
                    raise TecnoalarmAPIError(
                        f"Delete push notification failed: {resp.status}"
                    )
                return True
        except aiohttp.ClientError as e:
            raise TecnoalarmAPIError(f"Network error deleting push notification: {e}")

    # ---------- Internal Helpers ----------

    async def _validate_pin(self, pin: str) -> None:
        """
        Validate PIN with the server (in production, this would be called
        before any sensitive operation).
        """
        # For now, just check if PIN matches stored one
        stored_pin = self._session.get_pin()
        if stored_pin and stored_pin != pin:
            raise TecnoalarmPINRequired("Invalid PIN")
        elif not stored_pin:
            # No PIN stored yet, store this one
            self._session.set_pin(pin)
