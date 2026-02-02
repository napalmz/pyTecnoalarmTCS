# Tecnoalarm TCS Python Client

Python library for controlling Tecnoalarm Evolution alarm systems via the TCS API.

## Features

- ✅ **Authentication Flow**: Handshake → Email Validation → Login with OTP → App Registration
- ✅ **Central Operations**: Programs, Zones, Remotes status
- ⚠️ **Alarm Control (planned)**: Arm/Disarm stubs present, endpoint not yet implemented
- ✅ **Logging**: View alarm logs and clear memory
- ✅ **Push Notifications**: Get notification count and details
- ✅ **Session Persistence**: Save/load sessions to avoid repeated OTP
- ✅ **Error Handling**: Comprehensive exception types

## Installation

```bash
pip install -e .
```

## Quick Start

```python
import asyncio
import aiohttp
from pyTecnoalarm_TCS import TecnoalarmClient, TecnoalarmOTPRequired

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
        
        # Step 4: Register app with central PIN
        await client.register_app("123456")
        
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

# Register app with central PIN
await client.register_app("1234")

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

### Alarm Control (planned)

The methods `arm_program` / `disarm_program` currently raise `NotImplementedError`
because the Tecnoalarm REST endpoints for arm/disarm have not yet been extracted
from HAR traffic. The PIN validation helper is in place; once the endpoint is
known the methods will be wired to the real API.

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
from pyTecnoalarm_TCS.persistence import SessionPersistence

persistence = SessionPersistence(storage_dir=".tecnoalarm")

# Save session after login
await client.login(email, password, otp)
persistence.save_session(client.session, email)

# Load session on next run (avoids OTP)
if persistence.load_session(client.session, email):
    print("Session restored!")
```

## File Structure

```text
pyTecnoalarm_TCS/
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
from pyTecnoalarm_TCS import (
    TecnoalarmError,           # Base exception
    TecnoalarmOTPRequired,     # OTP needed
    TecnoalarmPINRequired,     # PIN validation failed
    TecnoalarmAuthError,       # Wrong credentials
    TecnoalarmEmailNotFound,   # Email not registered
    TecnoalarmAPIError,        # Generic API error
    TecnoalarmNetworkError,    # Network issues
)
```

## PIN Handling

The library handles PIN in multiple ways:

1. **Registration**: PIN is required after login to register the app
2. **Validation**: PIN is stored securely after registration
3. **Sensitive Operations**: Arm/disarm operations require PIN verification
4. **Storage**: PIN can be persisted to disk (should be encrypted in production)

```python
# Set PIN during registration
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

- `Authorization: Bearer {token}`
- `X-App-Id: {app_id}`
- `atype: app`
- `lang: it`
- `ver: 1.0`

## Notes

- All passwords are sent in plaintext to the API (HTTPS only)
- OTP is valid for a limited time after login attempt
- PIN is required for sensitive operations and must match registered PIN
- Responses are often base64-encoded JSON
- Some endpoints require initial handshake for service discovery

## License

MIT

## Support

For issues or questions, please check the HAR file analysis and example.py for reference implementations.
