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
    """Program (armed state) data"""
    index: int
    name: str | None
    status: int  # 0=disarmed, 1=day, 2=night, 3=away
    prealarm: bool
    alarm: bool
    memory_alarm: bool
    free: bool

    @property
    def status_name(self) -> str:
        return PROGRAM_STATUS.get(self.status, "unknown")

    @property
    def display_name(self) -> str:
        return self.name or f"Program {self.index}"


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
            
            # Always call monitor 3 times (even if previously activated)
            # This ensures server-side session state is kept fresh
            for i in range(3):
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
    
    async def get_programs(self) -> list[Program]:
        """
        Get list of programs (armed states).
        Implements automatic retry if the server returns an empty list,
        which can happen if the central session is in a transient invalid state.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

        async def _fetch_programs_once() -> list[Program]:
            """Internal method to fetch programs once."""
            try:
                # Activate central session FIRST
                await self._activate_central_session()
                
                # CRITICAL: Call monitor ONE MORE TIME immediately before GET /program
                # (The browser does this right before each GET endpoint)
                if self._session.central_type and self._session.central_id:
                    monitor_path = f"/monitor/{self._session.central_type}.{self._session.central_id}"
                    async with self._session._session.get(
                        self._session.tcs_url(monitor_path),
                        headers=self._session.tcs_headers(),
                    ) as resp:
                        pass  # Discard response, just need the call
                
                async with self._session._session.get(
                    self._session.tcs_url(TCS_PROGRAM),
                    headers=self._session.tcs_headers(),
                ) as resp:
                    if resp.status != 200:
                        raise TecnoalarmAPIError(f"Get programs failed: {resp.status}")

                    response_data = await resp.text()
                    
                    # Handle empty response
                    if not response_data:
                        import sys
                        print("[WARN] GET /program returned empty response", file=sys.stderr)
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
                            print(f"[ERROR] Failed to decode programs response: {decode_err}", file=sys.stderr)
                            print(f"[ERROR] Raw response ({len(response_data)} bytes): {response_data[:200]}", file=sys.stderr)
                            return []

                    programs = []
                    if isinstance(data, list):
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
                    else:
                        import sys
                        print(f"[ERROR] GET /program response is not a list, got {type(data).__name__}: {str(data)[:200]}", file=sys.stderr)

                    return programs
            except aiohttp.ClientError as e:
                raise TecnoalarmAPIError(f"Network error getting programs: {e}")
        
        # First attempt with normal rate limiting
        programs = await _fetch_programs_once()
        
        # If empty, retry with forced session reset
        if not programs:
            import sys
            print("[RETRY] Programs list is empty, retrying with forced reactivation...", file=sys.stderr)
            
            # Reset rate limiter to force full activation on next zone poll
            self._last_zone_activation = 0.0
            
            # Wait a tiny bit before retry
            await asyncio.sleep(0.2)
            
            # Retry once
            programs = await _fetch_programs_once()
            
            if not programs:
                print("[WARN] Programs still empty after retry", file=sys.stderr)
        
        return programs

    async def arm_program(self, program_idx: int, mode: int) -> bool:
        """
        Arm a specific program with the specified mode.
        
        Args:
            program_idx: Program index (0-3)
            mode: Arm mode - 1=day, 2=night, 3=away
        
        Returns:
            True if successful
        
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

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

    async def disarm_program(self, program_idx: int) -> bool:
        """
        Disarm a specific program.
        
        Args:
            program_idx: Program index (0-3)
        
        Returns:
            True if successful
        
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmAPIError: If API call fails
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

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
        Zones are polled frequently (every 1 second) but we rate limit
        the session activation to every 1 second to keep server load reasonable.
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

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
        Each boolean indicates if remote is OK (True) or has issues (False).
        """
        if not self._session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")

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
