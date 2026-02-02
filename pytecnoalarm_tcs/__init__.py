"""
Tecnoalarm TCS Python Client Library
"""
from .client import TecnoalarmClient
from .central import TecnoalarmCentral, Program, Zone, LogEntry
from .exceptions import (
    TecnoalarmError,
    TecnoalarmNotInitialized,
    TecnoalarmAuthError,
    TecnoalarmOTPRequired,
    TecnoalarmPINRequired,
    TecnoalarmEmailNotFound,
    TecnoalarmReauthRequired,
    TecnoalarmAPIError,
    TecnoalarmInvalidEmail,
    TecnoalarmNetworkError,
)

__version__ = "0.1.0"
__all__ = [
    "TecnoalarmClient",
    "TecnoalarmCentral",
    "Program",
    "Zone",
    "LogEntry",
    # Exceptions
    "TecnoalarmError",
    "TecnoalarmNotInitialized",
    "TecnoalarmAuthError",
    "TecnoalarmOTPRequired",
    "TecnoalarmPINRequired",
    "TecnoalarmEmailNotFound",
    "TecnoalarmReauthRequired",
    "TecnoalarmAPIError",
    "TecnoalarmInvalidEmail",
    "TecnoalarmNetworkError",
]