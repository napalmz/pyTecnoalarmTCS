"""
Session persistence utilities for saving/loading authentication data.
"""
import json
import os
import base64
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from .session import TecnoalarmSession

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    InvalidToken = Exception


class SessionPersistence:
    """
    Handles saving and loading session data to/from disk.
    
    Supports optional encryption of sensitive fields (token, tcs_token, pin).
    
    Useful for:
    - Persisting token between app restarts
    - Avoiding OTP requirement on every login
    - Storing PIN securely with encryption
    
    Args:
        storage_dir: Directory for session file (default: .tecnoalarm)
        encryption_key: Optional encryption key (32 bytes base64).
                       If None, uses machine-specific key.
                       If "disabled", no encryption.
    """

    def __init__(
        self, 
        storage_dir: str = ".tecnoalarm",
        encryption_key: Optional[str] = None
    ):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        # Create sessions subdirectory for session files
        self.sessions_dir = self.storage_dir / "sessions"
        self.sessions_dir.mkdir(exist_ok=True)
        
        # Setup encryption
        self._fernet = None
        if encryption_key != "disabled":
            if CRYPTO_AVAILABLE:
                if encryption_key:
                    # Use provided key
                    self._fernet = Fernet(encryption_key.encode())
                else:
                    # Generate machine-specific key
                    self._fernet = Fernet(self._get_machine_key())
            # If crypto not available, silently fall back to plaintext
    
    def get_sessions_dir(self) -> str:
        """Get absolute path to sessions directory.
        
        Returns:
            Absolute path to the directory containing session files
        """
        return str(self.sessions_dir.absolute())
    
    def get_session_file(self, email: str) -> str:
        """Get absolute path to session file for specific email.
        
        Args:
            email: Email address
            
        Returns:
            Absolute path to the session file
        """
        sanitized = email.replace("@", "_").replace(".", "_")
        session_file = self.sessions_dir / f"session_{sanitized}.json"
        return str(session_file.absolute())
    
    def _get_session_file(self, email: str) -> Path:
        """Get session file path for a specific email (internal)."""
        # Sanitize email for filename (replace @ and . with _)
        sanitized = email.replace("@", "_").replace(".", "_")
        return self.sessions_dir / f"session_{sanitized}.json"
    
    def _get_machine_key(self) -> bytes:
        """Generate a machine-specific encryption key."""
        # Use machine ID + storage path as seed
        import uuid
        import platform
        
        seed = f"{uuid.getnode()}-{platform.node()}-{self.storage_dir.absolute()}"
        key_bytes = hashlib.sha256(seed.encode()).digest()
        return base64.urlsafe_b64encode(key_bytes)
    
    def _encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        if not self._fernet:
            return value
        return self._fernet.encrypt(value.encode()).decode()
    
    def _decrypt(self, value: str) -> str:
        """Decrypt a string value."""
        if not self._fernet:
            return value
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except (InvalidToken, Exception):
            # If decryption fails, assume it's plaintext (backward compat)
            return value

    def save_session(
        self,
        session: TecnoalarmSession,
        email: str,
        password_hash: Optional[str] = None,
    ) -> None:
        """
        Save session data to disk with optional encryption.
        
        Args:
            session: TecnoalarmSession instance
            email: User email (used as identifier and filename)
            password_hash: Optional password hash
        """
        # Encrypt sensitive fields
        token = self._encrypt(session.token) if session.token else None
        tcs_token = self._encrypt(session.tcs_token) if session.tcs_token else None
        pin_value = session.get_pin()
        pin = self._encrypt(pin_value) if pin_value else None
        
        # Normalize program_names to avoid duplicates / invalid keys
        normalized_program_names: dict[str, str] = {}
        for k, v in (session.program_names or {}).items():
            try:
                key_str = str(int(k))
            except (ValueError, TypeError):
                key_str = str(k)
            if v is None:
                continue
            value_str = str(v).strip()
            if value_str:
                normalized_program_names[key_str] = value_str

        data = {
            "email": email,
            "account_base": session.account_base,
            "tcs_base": session.tcs_base,
            "token": token,
            "app_id": session.app_id,
            "account_id": session.account_id,
            "central_type": session.central_type,
            "central_id": session.central_id,
            "program_names": normalized_program_names,
            "tcs_token": tcs_token,
            "tcs_token_expiration": session.tcs_token_expiration,
            "pin": pin,
            "_encrypted": self._fernet is not None,  # Flag for decryption
        }

        if password_hash:
            data["password_hash"] = password_hash

        session_file = self._get_session_file(email)
        with open(session_file, "w") as f:
            json.dump(data, f, indent=2)

    def load_session(self, session: TecnoalarmSession, email: str) -> bool:
        """
        Load session data from disk and decrypt if needed.
        
        Args:
            session: TecnoalarmSession instance to populate
            email: User email to look up (used as filename identifier)
            
        Returns:
            True if session was loaded, False if not found or invalid
        """
        session_file = self._get_session_file(email)
        if not session_file.exists():
            return False

        try:
            with open(session_file, "r") as f:
                data = json.load(f)

            if data.get("email") != email:
                return False

            # Decrypt sensitive fields if they were encrypted
            token = self._decrypt(data.get("token")) if data.get("token") else None
            tcs_token = self._decrypt(data.get("tcs_token")) if data.get("tcs_token") else None
            pin = self._decrypt(data.get("pin")) if data.get("pin") else None

            # Restore session data
            session.account_base = data.get("account_base")
            session.tcs_base = data.get("tcs_base")
            session.token = token
            session.app_id = data.get("app_id")
            session.account_id = data.get("account_id")
            session.central_type = data.get("central_type")
            session.central_id = data.get("central_id")
            # Normalize program_names (dict or list)
            raw_program_names = data.get("program_names", {}) or {}
            normalized_program_names: dict[int, str] = {}
            if isinstance(raw_program_names, dict):
                for k, v in raw_program_names.items():
                    try:
                        key_int = int(k)
                    except (ValueError, TypeError):
                        continue
                    if v is None:
                        continue
                    value_str = str(v).strip()
                    if value_str:
                        normalized_program_names[key_int] = value_str
            elif isinstance(raw_program_names, list):
                for idx, item in enumerate(raw_program_names):
                    if isinstance(item, dict):
                        name = item.get("description") or item.get("descr") or item.get("name") or item.get("label")
                        if isinstance(name, str) and name.strip():
                            normalized_program_names[idx] = name.strip()
            session.program_names = normalized_program_names
            
            # Restore TCS-Token if available
            tcs_expiration = data.get("tcs_token_expiration")
            if tcs_token:
                session.set_tcs_token(tcs_token, tcs_expiration)

            if pin:
                session.set_pin(pin)

            return True
        except (json.JSONDecodeError, OSError):
            return False

    def clear_session(self, email: str) -> None:
        """Delete saved session data for specific email."""
        session_file = self._get_session_file(email)
        if session_file.exists():
            session_file.unlink()

    def get_saved_email(self) -> Optional[str]:
        """Get email from last saved session (checks default session.json for backward compatibility)."""
        # For backward compatibility, check old session.json file
        old_session_file = self.storage_dir / "session.json"
        if not old_session_file.exists():
            return None

        try:
            with open(old_session_file, "r") as f:
                data = json.load(f)
            return data.get("email")
        except (json.JSONDecodeError, OSError):
            return None
