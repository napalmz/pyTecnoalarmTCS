# pytecnoalarm-tcs

Async Python library for controlling Tecnoalarm Evolution alarm systems via the TCS API.

## Features

- ✅ **Authentication Flow**: Handshake → Email Validation → Login with OTP → App Registration
- ✅ **Auto PIN discovery**: `register_app()` can fetch PIN from `/tps`
- ✅ **Central Operations**: Programs, Zones, Remotes status
- ✅ **Alarm Control (experimental)**: Arm/Disarm via `/program/{idx}/on|off`
- ✅ **Logging**: View alarm logs and clear memory
- ✅ **Push Notifications**: Get notification count and details
- ✅ **Session Persistence**: Save/load sessions to avoid repeated OTP (optional encryption)
- ✅ **Session Reliability**: Automatic activation + retry on transient empty program list
- ✅ **Token Expiration Handling**: 401 → `TecnoalarmReauthRequired`
- ✅ **Error Handling**: Comprehensive exception types

## Installation

```bash
pip install -e .
```

> Nota: `cryptography` è usato per cifrare sessioni e PIN su disco.

## Quick Start

```python
import asyncio
import aiohttp
from pytecnoalarm_tcs import TecnoalarmClient, TecnoalarmOTPRequired

async def main():
    async with aiohttp.ClientSession() as session:
        client = TecnoalarmClient(session)
        
        # Step 1: Handshake
        await client.handshake()
        
        # Step 2: Validate email
        await client.validate_email("user@example.com")
        
        # Step 3: Login (will raise TecnoalarmOTPRequired)
        try:
            await client.login("user@example.com", "password")
        except TecnoalarmOTPRequired:
            otp = input("Enter OTP from email: ")
            await client.login("user@example.com", "password", otp)
        
        # Step 4: Register app (PIN is auto-discovered if not provided)
        await client.register_app()
        
        # Step 5: Get central status
        programs = await client.get_programs()
        zones = await client.get_zones()
        
        # Step 6: Logout
        await client.logout()

asyncio.run(main())
```

## API Overview

### Authentication

```python
# Handshake (get service endpoints)
await client.handshake()

# Validate email exists
is_valid = await client.validate_email("email@example.com")

# Login with password (first call)
try:
    await client.login("email@example.com", "password")
except TecnoalarmOTPRequired:
    pass  # User receives OTP via email

# Login with OTP (second call)
await client.login("email@example.com", "password", otp="123456")

# Register app with central PIN (optional)
await client.register_app()       # Auto-discover PIN
await client.register_app("1234")  # Explicit PIN override

# Logout
await client.logout()
```

### Central Data

```python
# Get all programs (armed states)
programs = await client.get_programs()
for prog in programs:
    print(f"Program {prog.index}: {prog.status_name}")

# Get all zones with status
zones = await client.get_zones()
for zone in zones:
    if zone.allocated:
        print(f"Zone: {zone.description} - {zone.status}")

# Get wireless remotes status
remotes = await client.get_remotes()

# Get central status (all in one)
status = await client.get_central_status()
```

### Alarm Control (experimental)

Arm/disarm uses `/program/{idx}/on` and `/program/{idx}/off` endpoints extracted
from HAR traffic. If the server rejects the call, you may need to re-register the app
or verify the PIN.

### Logs and Notifications

```python
# Get recent alarm logs
logs = await client.get_logs(from_id=0)

# Clear alarm memory
await client.clear_alarm_memory()

# Get push notifications
notifications = await client.get_push_notifications(take=10)
```

### Session Persistence

```python
from pytecnoalarm_tcs.persistence import SessionPersistence

persistence = SessionPersistence(storage_dir=".tecnoalarm")

# Save session after login
await client.login(email, password, otp)
persistence.save_session(client.session, email)

# Load session on next run (avoids OTP)
if persistence.load_session(client.session, email):
    print("Session restored!")

# Optional: disable encryption
persistence = SessionPersistence(storage_dir=".tecnoalarm", encryption_key="disabled")
```

## File Structure

```text
pytecnoalarm_tcs/
├── __init__.py           # Main exports
├── client.py             # Main public API
├── session.py            # Session state management
├── auth.py               # Authentication flows (includes SSE sync/dual POST tp)
├── central.py            # Alarm central operations
├── persistence.py        # Session save/load
├── constants.py          # API endpoints and constants
└── exceptions.py         # Custom exceptions
```

## Data Models

### Program

```python
@dataclass
class Program:
    index: int              # Program number (0-3)
    status: int             # 0=disarmed, 1=day, 2=night, 3=away
    status_name: str        # "disarmed", "armed_day", etc.
    prealarm: bool
    alarm: bool
    memory_alarm: bool
    free: bool
```

### Zone

```python
@dataclass
class Zone:
    index: int
    description: str        # Zone name
    status: str             # "CLOSED" or "OPEN"
    allocated: bool         # Is this zone used?
    in_supervision: bool
    in_low_battery: bool
    in_fail: bool
```

## Exception Handling

```python
from pytecnoalarm_tcs import (
    TecnoalarmError,           # Base exception
    TecnoalarmOTPRequired,     # OTP needed
    TecnoalarmPINRequired,     # PIN validation failed
    TecnoalarmAuthError,       # Wrong credentials
    TecnoalarmEmailNotFound,   # Email not registered
    TecnoalarmReauthRequired,  # Token expired or invalid
    TecnoalarmAPIError,        # Generic API error
    TecnoalarmInvalidEmail,    # Invalid email format
    TecnoalarmNetworkError,    # Network issues
)
```

## PIN Handling

The library handles PIN in multiple ways:

1. **Registration**: PIN is required after login to register the app
2. **Auto-discovery**: If PIN not provided, it is fetched from `/tps`
3. **Validation**: PIN is stored after registration
4. **Sensitive Operations**: Arm/disarm operations require PIN verification
5. **Storage**: PIN can be persisted to disk (encrypted if `cryptography` is available)

```python
# Set PIN during registration (optional)
await client.register_app()
await client.register_app("1234")

# PIN is automatically validated for sensitive operations
await client.arm_program(0, pin="1234")  # Must match registered PIN
```

## Central API Endpoints (from HAR)

```bash
GET   /account/handshake              # Get service endpoints
GET   /account/email/{email}          # Validate email (207 = exists)
POST  /account/login                  # Login without OTP (202 = OTP needed)
POST  /account/login?otp=XXX          # Login with OTP (200 = success)

GET   /tcsRC/tps                      # List centrals
GET   /tcsRC/monitor/{tp_type}.{id}   # Monitor central status
GET   /tcsRC/tpstatus/sse?quick=true  # SSE sync (programs/zones)
PUT   /tcsRC/tp                       # Register app (with PIN)
DELETE /tcsRC/tp                      # Unregister app

GET   /tcsRC/program                  # Get programs
GET   /tcsRC/zone                     # Get zones
GET   /tcsRC/remote                   # Get remotes
GET   /tcsRC/log/{from_id}            # Get logs
DELETE /tcsRC/tp/memory               # Clear alarm memory

GET   /tcsRC/push/count               # Push notification count
GET   /tcsRC/push?take=N              # Get notifications
```

## Authentication Headers

All TCS requests include:

- `Auth: {token}`
- `X-App-Id: {app_id}`
- `TCS-Token: {tcs_token}` (present on registered endpoints)
- `atype: app`
- `lang: it`
- `ver: 1.0`
- `Accept: application/json, text/plain, */*`

## Notes

- All passwords are sent in plaintext to the API (HTTPS only)
- OTP is valid for a limited time after login attempt
- PIN is required for sensitive operations and must match registered PIN
- Responses are often base64-encoded JSON
- Some endpoints require initial handshake for service discovery
- Programs can briefly return empty when server session is stale; automatic retry is in place
- Tokens expire after ~24h; re-authenticate if `TecnoalarmReauthRequired` is raised

## License

MIT

## Support

Per problemi o domande, apri una issue su GitHub e allega i log con `DEBUG`.
