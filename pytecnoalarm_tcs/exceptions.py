class TecnoalarmError(Exception):
    """Base exception"""


class TecnoalarmNotInitialized(TecnoalarmError):
    """Handshake not completed"""


class TecnoalarmAuthError(TecnoalarmError):
    """Invalid credentials or OTP"""


class TecnoalarmOTPRequired(TecnoalarmError):
    """OTP required to continue login"""


class TecnoalarmReauthRequired(TecnoalarmError):
    """Token expired or invalid"""


class TecnoalarmPINRequired(TecnoalarmError):
    """PIN required for sensitive operation"""


class TecnoalarmEmailNotFound(TecnoalarmError):
    """Email not registered"""


class TecnoalarmAPIError(TecnoalarmError):
    """Generic API error"""


class TecnoalarmInvalidEmail(TecnoalarmError):
    """Invalid email format or not found"""


class TecnoalarmNetworkError(TecnoalarmError):
    """Network error"""