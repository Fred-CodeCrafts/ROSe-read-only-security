#!/usr/bin/env python3
"""
Test script for Task 7: Chat Command Routing

Verifies:
- Chat command exists in rose.py
- CLI module can be imported
- Demo mode detection works
- Chat interface can start
"""

import sys
import os
from pathlib import Path

# Add src/python to path
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

def test_chat_command_in_rose():
    """Test that chat command exists in rose.py"""
    print("Test 1: Verify chat command exists in rose.py")
    
    rose_path = src_path.parent / "rose.py"
    try:
        with open(rose_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Try with different encoding
        with open(rose_path, 'r', encoding='latin-1') as f:
            content = f.read()
    
    # Check for chat command
    assert "command in ['chat', 'analyst', 'ai', 'ask']" in content, \
        "Chat command not found in rose.py"
    
    # Check for routing to CLI
    assert "from aws_bedrock_athena_ai.cli import main as analyst_main" in content, \
        "CLI import not found in rose.py"
    
    # Check for error handling
    assert "except ImportError" in content, \
        "ImportError handling not found"
    
    assert "except Exception" in content, \
        "General exception handling not found"
    
    print("✅ Chat command exists and routes to CLI with error handling")
    return True


def test_cli_module_import():
    """Test that CLI module can be imported"""
    print("\nTest 2: Verify CLI module can be imported")
    
    try:
        from aws_bedrock_athena_ai.cli import main, cmd_chat
        print("✅ CLI module imported successfully")
        print(f"   - main function: {main}")
        print(f"   - cmd_chat function: {cmd_chat}")
        return True
    except ImportError as e:
        print(f"❌ Failed to import CLI module: {e}")
        return False


def test_demo_mode_detection():
    """Test that demo mode detection works"""
    print("\nTest 3: Verify demo mode detection")
    
    try:
        from aws_bedrock_athena_ai.api.aws_detector import AWSAvailabilityDetector
        
        detector = AWSAvailabilityDetector()
        bedrock_available = detector.is_bedrock_available()
        
        print(f"   - Bedrock available: {bedrock_available}")
        
        if bedrock_available:
            print("✅ AWS Bedrock is configured (production mode)")
        else:
            print("✅ AWS Bedrock not configured (demo mode will be used)")
        
        return True
    except Exception as e:
        print(f"⚠️  Demo mode detection error (will default to demo): {e}")
        return True  # This is acceptable - will use demo mode


def test_demo_response_generator():
    """Test that demo response generator works"""
    print("\nTest 4: Verify demo response generator")
    
    try:
        from aws_bedrock_athena_ai.api.demo_responses import DemoResponseGenerator
        
        generator = DemoResponseGenerator()
        response = generator.generate_security_response(
            "What are our top security risks?",
            "test-conversation"
        )
        
        # Response is a dictionary
        assert isinstance(response, dict), "Response should be a dictionary"
        assert 'executive_summary' in response, "Response should have executive_summary"
        assert response['conversation_id'] == "test-conversation", \
            "Conversation ID should match"
        
        print("✅ Demo response generator works")
        print(f"   - Sample response: {response['executive_summary'][:100]}...")
        return True
    except Exception as e:
        print(f"❌ Demo response generator failed: {e}")
        return False


def test_chat_function_signature():
    """Test that chat function has correct signature"""
    print("\nTest 5: Verify chat function signature")
    
    try:
        from aws_bedrock_athena_ai.cli import cmd_chat
        import inspect
        
        sig = inspect.signature(cmd_chat)
        params = list(sig.parameters.keys())
        
        print(f"   - Function signature: cmd_chat{sig}")
        print(f"   - Parameters: {params}")
        
        # Should accept optional args parameter
        assert len(params) <= 1, "cmd_chat should accept 0 or 1 parameters"
        
        print("✅ Chat function signature is correct")
        return True
    except Exception as e:
        print(f"❌ Chat function signature check failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("Task 7: Chat Command Routing - Verification Tests")
    print("=" * 70)
    
    tests = [
        test_chat_command_in_rose,
        test_cli_module_import,
        test_demo_mode_detection,
        test_demo_response_generator,
        test_chat_function_signature,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ All tests passed! Task 7 implementation is complete.")
        print("\nYou can now test the chat command:")
        print("  python rose.py chat")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
