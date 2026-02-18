"""
Quick test to verify demo mode authentication works.
"""

import os
import sys

# Set demo mode for testing
os.environ['DEMO_MODE'] = 'true'

from aws_bedrock_athena_ai.api.auth import get_auth_mode, AuthMode, aws_detector

def test_demo_mode_detection():
    """Test that demo mode is correctly detected"""
    print("Testing demo mode detection...")
    
    # Clear cache to force fresh check
    aws_detector.clear_cache()
    
    # Check auth mode
    mode = get_auth_mode()
    print(f"Auth mode: {mode}")
    
    assert mode == AuthMode.DEMO, f"Expected DEMO mode, got {mode}"
    print("✓ Demo mode correctly detected")
    
    # Check AWS availability
    bedrock_available = aws_detector.is_bedrock_available()
    print(f"Bedrock available: {bedrock_available}")
    assert not bedrock_available, "Bedrock should not be available in demo mode"
    print("✓ Bedrock correctly reported as unavailable")
    
    # Check availability status
    status = aws_detector.get_availability_status()
    print(f"Availability status: {status}")
    assert status['mode'] == 'demo', f"Expected demo mode in status, got {status['mode']}"
    print("✓ Availability status correct")
    
    print("\n✅ All demo mode tests passed!")

if __name__ == "__main__":
    try:
        test_demo_mode_detection()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
