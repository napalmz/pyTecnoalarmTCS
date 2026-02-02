"""
Tecnoalarm TCS Alarm System Client

Main public API for interacting with Tecnoalarm Evolution alarm central.
"""
import aiohttp
from .session import TecnoalarmSession
from .auth import TecnoalarmAuth
from .central import TecnoalarmCentral
from .exceptions import TecnoalarmNotInitialized


class TecnoalarmClient:
    """
    Main client for Tecnoalarm API.
    
    Usage:
        async with aiohttp.ClientSession() as session:
            client = TecnoalarmClient(session)
            
            # 1. Handshake
            await client.handshake()
            
            # 2. Validate email
            is_valid = await client.validate_email("user@example.com")
            
            # 3. Login (will raise TecnoalarmOTPRequired)
            try:
                await client.login("user@example.com", "password")
            except TecnoalarmOTPRequired:
                # User receives OTP via email
                otp = input("Enter OTP: ")
                await client.login("user@example.com", "password", otp)
            
            # 4. Register app with PIN
            await client.register_app("1234")
            
            # 5. Get central status
            status = await client.get_central_status()
            
            # 6. Work with central
            programs = await client.get_programs()
            zones = await client.get_zones()
            
            # 7. Logout
            await client.logout()
    """

    def __init__(self, aiohttp_session: aiohttp.ClientSession):
        self.session = TecnoalarmSession(aiohttp_session)
        self.auth = TecnoalarmAuth(self.session)
        self.central = TecnoalarmCentral(self.session)
        self.persistence = None  # Set via set_persistence()

    # ========== Auth Flow ==========

    async def handshake(self) -> None:
        """
        Initial handshake to get service endpoints.
        Must be called before login().
        """
        await self.auth.handshake()

    async def validate_email(self, email: str) -> bool:
        """
        Check if email is registered in Tecnoalarm system.
        
        Returns:
            True if email exists, False otherwise
            
        Raises:
            TecnoalarmEmailNotFound: If email is not registered
        """
        if not self.session.is_handshaken:
            raise TecnoalarmNotInitialized("Call handshake() first")
        return await self.auth.validate_email(email)

    async def login(
        self, email: str, password: str, otp: str | None = None
    ) -> None:
        """
        Login with email and password.
        
        First call without OTP will raise TecnoalarmOTPRequired.
        User receives OTP via email, then call again with otp parameter.
        
        Args:
            email: Email address
            password: Password (sent in plaintext to API)
            otp: One-time password (only on second call)
            
        Raises:
            TecnoalarmNotInitialized: If handshake not called
            TecnoalarmOTPRequired: If OTP needed (first call)
            TecnoalarmAuthError: If credentials invalid
        """
        if not self.session.is_handshaken:
            raise TecnoalarmNotInitialized("Call handshake() first")
        await self.auth.login(email, password, otp)

    async def register_app(self, pin: str | None = None) -> None:
        """
        Register this app instance with the alarm central PIN.
        
        Must be called after successful login() before accessing central data.
        
        Args:
            pin: Optional 4-6 digit PIN of the alarm central.
                 If not provided, PIN is fetched automatically from server.
            
        Raises:
            TecnoalarmNotInitialized: If not authenticated
            TecnoalarmPINRequired: If PIN is invalid
        """
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Call login() first")
        await self.auth.register_app(pin)

    async def logout(self) -> None:
        """
        Logout and unregister app from central.
        """
        await self.auth.logout()

    async def refresh_token(self) -> None:
        """
        Refresh TCS-Token without login.
        Useful if token is about to expire or after 401 errors.
        """
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        await self.auth.refresh_tcs_token()

    # ========== Central Operations ==========

    async def get_central_status(self) -> dict:
        """Get complete central status (programs, zones, remotes)"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_central_status()

    async def get_central_list(self) -> dict:
        """Get list of all centrals for this account"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_central_list()

    async def monitor_central(self, tp_type: str, central_id: str) -> dict:
        """
        Monitor central status by polling endpoint.
        
        Args:
            tp_type: Central type (e.g., "tp042")
            central_id: Central serial number (e.g., "003236056")
        """
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.monitor_central(tp_type, central_id)

    async def get_programs(self) -> list:
        """Get list of programs (armed states)"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_programs()

    async def get_zones(self) -> list:
        """Get list of zones with status"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_zones()

    async def get_remotes(self) -> list:
        """Get list of wireless remotes status"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_remotes()

    async def arm_program(self, program_idx: int, mode: int = 3, pin: str | None = None) -> bool:
        """
        Arm a specific program with the specified mode.
        
        Args:
            program_idx: Program index (0-3)
            mode: Arm mode - 1=day, 2=night, 3=armed (default: 3 for standard ON)
            pin: PIN for security validation (required)
            
        Returns:
            True if successful
            
        Raises:
            TecnoalarmPINRequired: If PIN is missing or incorrect
            
        Note:
            Most systems use mode=3 (armed/ON) and mode=0 (disarmed/OFF).
            Modes 1 (day) and 2 (night) are for advanced systems only.
        """
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.arm_program(program_idx, mode, pin)

    async def disarm_program(self, program_idx: int, pin: str | None = None) -> bool:
        """
        Disarm a specific program.
        
        Args:
            program_idx: Program index (0-3)
            pin: PIN for security validation (required)
            
        Returns:
            True if successful
            
        Raises:
            TecnoalarmPINRequired: If PIN is missing or incorrect
        """
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.disarm_program(program_idx, pin)

    async def get_logs(self, from_id: int = 0, limit: int = 100) -> list:
        """Get alarm system logs"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_logs(from_id, limit)

    async def clear_alarm_memory(self) -> None:
        """Clear alarm memory"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        await self.central.clear_alarm_memory()

    async def get_push_notifications(self, take: int = 10) -> list:
        """Get recent push notifications"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.get_push_notifications(take)

    async def mark_all_push_as_read(self) -> bool:
        """Mark all push notifications as read"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.mark_all_push_as_read()

    async def mark_push_notifications_as_read(self, notifications: list[dict]) -> bool:
        """Mark specific push notifications as read"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.mark_push_notifications_as_read(notifications)

    async def delete_push_notification(self, notification_id: int) -> bool:
        """Delete a specific push notification"""
        if not self.session.is_authenticated:
            raise TecnoalarmNotInitialized("Not authenticated")
        return await self.central.delete_push_notification(notification_id)

    # ========== Session Management ==========

    def set_persistence(self, persistence) -> None:
        """Set persistence handler for session management."""
        self.persistence = persistence

    def clear_saved_session(self, email: str) -> None:
        """Delete saved session data for a specific email.
        
        Args:
            email: Email address whose session file should be deleted
            
        Raises:
            ValueError: If persistence is not configured
        """
        if not self.persistence:
            raise ValueError("Persistence not configured. Call set_persistence() first.")
        self.persistence.clear_session(email)

    def get_sessions_directory(self) -> str:
        """Get absolute path to directory containing session files.
        
        Useful for debugging or monitoring saved sessions from HA.
        
        Returns:
            Absolute path to sessions directory
            
        Raises:
            ValueError: If persistence is not configured
        """
        if not self.persistence:
            raise ValueError("Persistence not configured. Call set_persistence() first.")
        return self.persistence.get_sessions_dir()

    def get_session_file_path(self, email: str) -> str:
        """Get absolute path to session file for specific email.
        
        Useful for debugging or monitoring session file creation.
        
        Args:
            email: Email address
            
        Returns:
            Absolute path to the session file
            
        Raises:
            ValueError: If persistence is not configured
        """
        if not self.persistence:
            raise ValueError("Persistence not configured. Call set_persistence() first.")
        return self.persistence.get_session_file(email)