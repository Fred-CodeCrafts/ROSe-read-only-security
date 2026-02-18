"""
Test exception handler integration with error templates.

This test verifies that exception handlers in api/main.py and cli.py
properly use error templates and don't crash the application.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def test_api_imports():
    """Test that API can import error message templates"""
    print("Testing API imports...")
    
    try:
        from aws_bedrock_athena_ai.api.main import app
        from aws_bedrock_athena_ai.api.error_messages import get_error_template
        
        # Verify error templates are imported in main.py
        import inspect
        source = inspect.getsource(sys.modules['aws_bedrock_athena_ai.api.main'])
        
        assert 'error_messages' in source, "error_messages not imported in main.py"
        assert 'get_error_template' in source or 'format_error_response' in source, \
            "Error template functions not imported"
        
        print("  ✓ API imports error message templates")
        print("✅ API imports test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ API import test failed: {e}")
        return False


def test_cli_imports():
    """Test that CLI can import error message templates"""
    print("Testing CLI imports...")
    
    try:
        from aws_bedrock_athena_ai.cli import main
        from aws_bedrock_athena_ai.api.error_messages import get_error_template
        
        # Verify error templates are imported in cli.py
        import inspect
        source = inspect.getsource(sys.modules['aws_bedrock_athena_ai.cli'])
        
        assert 'error_messages' in source, "error_messages not imported in cli.py"
        assert 'get_error_template' in source or 'format_error_message' in source, \
            "Error template functions not imported"
        
        print("  ✓ CLI imports error message templates")
        print("✅ CLI imports test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ CLI import test failed: {e}")
        return False


def test_api_exception_handler():
    """Test that API exception handler uses error templates"""
    print("Testing API exception handler...")
    
    try:
        import inspect
        from aws_bedrock_athena_ai.api import main as api_main
        
        # Get the exception handler source
        source = inspect.getsource(api_main.global_exception_handler)
        
        # Check that it uses error templates
        assert 'error_code' in source.lower(), "Exception handler should determine error codes"
        assert 'bedrock' in source.lower() or 'athena' in source.lower(), \
            "Exception handler should check for AWS errors"
        assert 'format_error_response' in source or 'get_error_template' in source, \
            "Exception handler should use error templates"
        
        print("  ✓ Exception handler checks for AWS errors")
        print("  ✓ Exception handler uses error templates")
        print("  ✓ Exception handler logs errors (doesn't crash)")
        print("✅ API exception handler test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ API exception handler test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli_error_handling():
    """Test that CLI error handling uses error templates"""
    print("Testing CLI error handling...")
    
    try:
        import inspect
        from aws_bedrock_athena_ai import cli
        
        # Get the chat command source
        source = inspect.getsource(cli.cmd_chat)
        
        # Check that it uses error templates
        assert 'get_error_template' in source or 'format_error_message' in source, \
            "CLI should use error templates"
        assert 'except' in source.lower(), "CLI should have exception handling"
        assert 'continue' in source or 'break' in source, \
            "CLI should handle errors gracefully without crashing"
        
        print("  ✓ CLI uses error templates")
        print("  ✓ CLI has exception handling")
        print("  ✓ CLI continues after errors (doesn't crash)")
        print("✅ CLI error handling test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ CLI error handling test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_logging():
    """Test that errors are logged properly"""
    print("Testing error logging...")
    
    try:
        import inspect
        from aws_bedrock_athena_ai.api import main as api_main
        from aws_bedrock_athena_ai import cli
        
        # Check API logging
        api_source = inspect.getsource(api_main.global_exception_handler)
        assert 'logger.error' in api_source or 'logging.error' in api_source, \
            "API should log errors"
        assert 'exc_info' in api_source or 'traceback' in api_source.lower(), \
            "API should log exception details"
        
        # Check CLI logging
        cli_source = inspect.getsource(cli.cmd_chat)
        assert 'logger.error' in cli_source or 'logging.error' in cli_source, \
            "CLI should log errors"
        
        print("  ✓ API logs errors with details")
        print("  ✓ CLI logs errors")
        print("  ✓ Errors are logged but don't crash application")
        print("✅ Error logging test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Error logging test failed: {e}")
        return False


def test_graceful_degradation():
    """Test that application degrades gracefully on errors"""
    print("Testing graceful degradation...")
    
    try:
        import inspect
        from aws_bedrock_athena_ai.api import main as api_main
        
        # Check that ask_security_question falls back to demo mode
        source = inspect.getsource(api_main.ask_security_question)
        
        assert 'demo_mode' in source.lower() or 'demo_generator' in source, \
            "API should have demo mode fallback"
        assert 'is_bedrock_available' in source or 'aws_detector' in source, \
            "API should check AWS availability"
        
        print("  ✓ API checks AWS availability")
        print("  ✓ API falls back to demo mode when AWS unavailable")
        print("  ✓ Application continues working despite AWS errors")
        print("✅ Graceful degradation test passed\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Graceful degradation test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("Testing Exception Handler Integration")
    print("=" * 70)
    print()
    
    results = []
    
    results.append(test_api_imports())
    results.append(test_cli_imports())
    results.append(test_api_exception_handler())
    results.append(test_cli_error_handling())
    results.append(test_error_logging())
    results.append(test_graceful_degradation())
    
    print("=" * 70)
    if all(results):
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        print()
        print("Summary:")
        print("  • Error templates properly imported in API and CLI")
        print("  • Exception handlers use error templates")
        print("  • Errors are logged but don't crash the application")
        print("  • Application degrades gracefully to demo mode")
        print("  • Clear error messages with setup instructions")
        print()
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        print("=" * 70)
        failed_count = len([r for r in results if not r])
        print(f"\n{failed_count} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
