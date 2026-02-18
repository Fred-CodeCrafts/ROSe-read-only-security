#!/usr/bin/env python3
"""
Test script to verify frontend demo mode implementation.
This tests that the frontend correctly handles demo mode.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_frontend_file_exists():
    """Test that the frontend JavaScript file exists"""
    frontend_path = os.path.join(
        os.path.dirname(__file__),
        'web', 'static', 'app.js'
    )
    assert os.path.exists(frontend_path), f"Frontend file not found: {frontend_path}"
    print("✓ Frontend file exists")
    return frontend_path

def test_frontend_has_demo_mode_support(frontend_path):
    """Test that frontend has demo mode support"""
    with open(frontend_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for /api/v1/status endpoint call
    assert '/api/v1/status' in content, "Frontend should call /api/v1/status endpoint"
    print("✓ Frontend calls /api/v1/status endpoint")
    
    # Check for mode parameter in setConnectionStatus
    assert "mode = 'unknown'" in content or 'mode = "unknown"' in content, \
        "setConnectionStatus should accept mode parameter"
    print("✓ setConnectionStatus accepts mode parameter")
    
    # Check for "Connected (Demo)" text
    assert 'Connected (Demo)' in content, \
        "Frontend should display 'Connected (Demo)' in demo mode"
    print("✓ Frontend displays 'Connected (Demo)' text")
    
    # Check for conditional Authorization header
    assert "apiKey !== 'demo'" in content or 'apiKey !== "demo"' in content, \
        "Frontend should conditionally add Authorization header"
    print("✓ Frontend conditionally adds Authorization header")
    
    # Check for demo stats initialization
    assert 'queriesToday = 12' in content or 'queriesToday=12' in content, \
        "Frontend should initialize demo stats"
    print("✓ Frontend initializes demo stats")
    
    # Check for demo mode detection
    assert "data.mode === 'demo'" in content or 'data.mode === "demo"' in content, \
        "Frontend should detect demo mode"
    print("✓ Frontend detects demo mode")
    
    # Check for flexible threats_found handling
    assert 'data.threats_found' in content, \
        "Frontend should handle threats_found at top level for demo responses"
    print("✓ Frontend handles demo response format")

def main():
    """Run all tests"""
    print("Testing Frontend Demo Mode Implementation")
    print("=" * 50)
    
    try:
        frontend_path = test_frontend_file_exists()
        test_frontend_has_demo_mode_support(frontend_path)
        
        print("\n" + "=" * 50)
        print("✅ All frontend demo mode tests passed!")
        print("\nImplemented features:")
        print("  • Connection status checks /api/v1/status")
        print("  • Displays 'Connected (Demo)' in demo mode")
        print("  • Conditionally adds Authorization header")
        print("  • Initializes stats with demo values")
        print("  • Handles demo response formats")
        return 0
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
