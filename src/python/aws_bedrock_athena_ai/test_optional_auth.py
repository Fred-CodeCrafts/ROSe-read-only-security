"""
Test optional_auth functionality in demo mode.
"""

import os
import sys
import asyncio

# Set demo mode for testing
os.environ['DEMO_MODE'] = 'true'

from fastapi import Request
from aws_bedrock_athena_ai.api.auth import optional_auth, get_auth_mode, AuthMode

async def test_optional_auth_demo_mode():
    """Test that optional_auth allows unauthenticated access in demo mode"""
    print("Testing optional_auth in demo mode...")
    
    # Verify we're in demo mode
    mode = get_auth_mode()
    print(f"Auth mode: {mode}")
    assert mode == AuthMode.DEMO, f"Expected DEMO mode, got {mode}"
    
    # Create a mock request without authentication
    class MockRequest:
        def __init__(self):
            self.headers = {}
    
    request = MockRequest()
    
    # Call optional_auth
    user_data = await optional_auth(request)
    print(f"User data: {user_data}")
    
    # Verify demo user data
    assert user_data['user_id'] == 'demo_user', f"Expected demo_user, got {user_data['user_id']}"
    assert user_data['mode'] == 'demo', f"Expected demo mode, got {user_data['mode']}"
    assert not user_data['authenticated'], "Expected authenticated=False"
    assert 'query' in user_data['permissions'], "Expected query permission"
    assert 'read' in user_data['permissions'], "Expected read permission"
    
    print("✓ optional_auth correctly allows unauthenticated access in demo mode")
    print("✓ Demo user has correct permissions")
    
    print("\n✅ All optional_auth tests passed!")

if __name__ == "__main__":
    try:
        asyncio.run(test_optional_auth_demo_mode())
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
