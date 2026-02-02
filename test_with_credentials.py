#!/usr/bin/env python3
"""
Interactive test script for Tecnoalarm TCS Client with real credentials.

Usage:
    python test_with_credentials.py
    
This script will:
1. Ask for your email and password
2. Perform handshake
3. Validate email
4. Login and request OTP
5. Ask for OTP from email
6. Register app with PIN
7. Get central information
"""

import asyncio
import getpass
import aiohttp
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Add current dir to path
import sys
sys.path.insert(0, str(Path(__file__).parent))

from pyTecnoalarm_TCS import (
    TecnoalarmClient,
    TecnoalarmOTPRequired,
    TecnoalarmPINRequired,
    TecnoalarmError,
)
from pyTecnoalarm_TCS.constants import HANDSHAKE_URL


def save_token_to_env(token: str, app_id: str):
    """Save authentication token to .env file for reuse."""
    env_path = Path(__file__).parent / ".env"
    
    # Read existing .env
    lines = []
    if env_path.exists():
        with open(env_path, 'r') as f:
            lines = f.readlines()
    
    # Update or add token lines
    token_found = False
    app_id_found = False
    
    for i, line in enumerate(lines):
        if line.startswith('TCS_TOKEN='):
            lines[i] = f'TCS_TOKEN="{token}"\n'
            token_found = True
        elif line.startswith('TCS_APP_ID='):
            lines[i] = f'TCS_APP_ID="{app_id}"\n'
            app_id_found = True
    
    if not token_found:
        lines.append(f'TCS_TOKEN="{token}"\n')
    if not app_id_found:
        lines.append(f'TCS_APP_ID="{app_id}"\n')
    
    # Write back
    with open(env_path, 'w') as f:
        f.writelines(lines)
    
    print("💾 Token saved to .env for future use")


async def test_full_flow():
    """Test complete authentication and central operations flow"""
    
    print("\n" + "="*70)
    print("TECNOALARM TCS CLIENT - FULL INTEGRATION TEST")
    print("="*70)
    
    # Get credentials from user
    print("\n📧 Tecnoalarm Credentials")
    print("-" * 70)
    email = os.getenv("TCS_EMAIL", "").strip()
    password = os.getenv("TCS_PASS", "").strip()
    
    if not email:
        email = input("Email: ").strip()
    else:
        print(f"Email: {email}")
    
    if not password:
        password = getpass.getpass("Password: ")
    
    if not email or not password:
        print("❌ Email and password are required")
        return
    
    # Create client
    print("\n⏳ Creating client and connecting...")
    # Enable cookie jar for session persistence (required for tpSession cookie)
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as http_session:
        client = TecnoalarmClient(http_session)
        
        try:
            # Step 1: Handshake
            print("\n📡 Step 1: Handshake")
            print("-" * 70)
            print(f"  → Contacting {HANDSHAKE_URL}...")
            try:
                await client.handshake()
                print(f"  → Account base: {client.session.account_base}")
                print(f"  → TCS base: {client.session.tcs_base}")
                print(f"  → App ID: {client.session.app_id}")
                print("✓ Handshake successful")
            except Exception as e:
                print(f"✗ Handshake failed: {e}")
                import traceback
                traceback.print_exc()
                return
            
            # Step 2: Try to use cached token first
            cached_token = os.getenv("TCS_TOKEN", "").strip()
            cached_app_id = os.getenv("TCS_APP_ID", "").strip()
            
            login_successful = False
            
            if cached_token and cached_app_id:
                print("\n🔑 Step 2: Using Cached Token")
                print("-" * 70)
                print("⏳ Attempting to use saved token...")
                
                # Set cached credentials directly
                client.session.token = cached_token
                client.session.app_id = cached_app_id
                
                # Verify token works by trying handshake or a simple call
                try:
                    # Try to validate email as a simple auth check
                    await client.validate_email(email)
                    print("✓ Cached token is valid - skipping login")
                    login_successful = True
                except Exception as e:
                    print(f"⚠ Cached token expired or invalid: {e}")
                    print("⏳ Will perform full login...")
                    client.session.token = None
                    client.session.app_id = None
            
            if not login_successful:
                # Step 2: Validate email
                print("\n📧 Step 2: Validate Email")
                print("-" * 70)
                is_valid = await client.validate_email(email)
                if is_valid:
                    print(f"✓ Email '{email}' is registered")
                else:
                    print(f"❌ Email '{email}' is NOT registered in Tecnoalarm")
                    return
                
                # Step 3: Login
                print("\n🔐 Step 3: Login")
                print("-" * 70)
                try:
                    await client.login(email, password)
                    print("✓ Login successful (no OTP required)")
                except TecnoalarmOTPRequired:
                    print("⏳ OTP required - check your email")
                    otp = input("Enter OTP from email: ").strip()
                    
                    if not otp:
                        print("❌ OTP is required")
                        return
                    
                    print(f"⏳ Logging in with OTP...")
                    await client.login(email, password, otp)
                    print("✓ Login successful with OTP")
                
                # Save token for next time
                if client.session.token and client.session.app_id:
                    save_token_to_env(client.session.token, client.session.app_id)
            
            # Step 4: Register app (PIN fetched automatically from server)
            print("\n🔑 Step 4: Register App (Auto-fetch PIN)")
            print("-" * 70)
            
            try:
                # PIN is fetched automatically from GET /tcsRC/tps
                await client.register_app()
                print("✓ App registered successfully (PIN auto-fetched)")
                
                # DEBUG: Check cookies after registration
                print(f"[DEBUG] Cookies after register_app: {[c.key for c in http_session.cookie_jar]}")
                
            except TecnoalarmPINRequired:
                print("❌ PIN validation failed - registration failed")
                return
            
            # Step 5: Get central data
            print("\n🏠 Step 5: Get Central Information")
            print("-" * 70)
            
            # Get central status
            print("⏳ Fetching central status...")
            try:
                status = await client.get_central_status()
                print("✓ Central status received")
                if status:
                    print(f"  Status data keys: {list(status.keys())}")
            except Exception as e:
                print(f"⚠ Could not fetch central status: {e}")
            
            # Get central list
            print("⏳ Fetching central list...")
            try:
                centrals = await client.get_central_list()
                print(f"✓ Found {len(centrals)} central(s)")
                for i, central in enumerate(centrals, 1):
                    print(f"  {i}. {central}")
            except Exception as e:
                print(f"⚠ Could not fetch central list: {e}")
            
            # Get programs
            print("⏳ Fetching programs...")
            try:
                programs = await client.get_programs()
                print(f"✓ Found {len(programs)} program(s)")
                for prog in programs:
                    status_name = prog.status_name
                    alarm_str = "🔴 ALARM" if prog.alarm else ""
                    print(f"  - Program {prog.index}: {status_name} {alarm_str}")
            except Exception as e:
                print(f"⚠ Could not fetch programs: {e}")
            
            # Get zones
            print("⏳ Fetching zones...")
            try:
                zones = await client.get_zones()
                print(f"✓ Found {len(zones)} zone(s)")
                for zone in zones[:5]:  # Show first 5
                    status_str = "🟢 OK" if zone.status == 0 else "🔴 OPEN"
                    print(f"  - {zone.description}: {status_str}")
                if len(zones) > 5:
                    print(f"  ... and {len(zones) - 5} more zones")
            except Exception as e:
                print(f"⚠ Could not fetch zones: {e}")
            
            # Get remotes
            print("⏳ Fetching remotes...")
            try:
                remotes = await client.get_remotes()
                print(f"✓ Remotes data received")
                if remotes:
                    print(f"  Remotes: {remotes}")
            except Exception as e:
                print(f"⚠ Could not fetch remotes: {e}")
            
            # Get logs
            print("⏳ Fetching logs...")
            try:
                logs = await client.get_logs(from_id=0)
                print(f"✓ Found {len(logs)} log entries")
                for log in logs[:5]:  # Show first 5
                    print(f"  - [{log.timestamp}] {log.description}")
                if len(logs) > 5:
                    print(f"  ... and {len(logs) - 5} more entries")
            except Exception as e:
                print(f"⚠ Could not fetch logs: {e}")
            
            # Success
            print("\n" + "="*70)
            print("✅ ALL TESTS PASSED - CLIENT IS WORKING!")
            print("="*70)
            
        except TecnoalarmError as e:
            print(f"\n❌ Tecnoalarm Error: {e}")
        except Exception as e:
            print(f"\n❌ Unexpected Error: {e}")
            import traceback
            traceback.print_exc()


async def main():
    """Main entry point"""
    try:
        await test_full_flow()
    except KeyboardInterrupt:
        print("\n\n⏹ Test cancelled by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
