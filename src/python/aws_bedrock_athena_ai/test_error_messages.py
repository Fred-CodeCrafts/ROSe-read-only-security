"""
Test error message templates implementation.

This test verifies that error messages are clear, include setup instructions,
and are properly integrated into exception handlers.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aws_bedrock_athena_ai.api.error_messages import (
    get_error_template,
    format_error_message,
    format_error_response,
    BEDROCK_NOT_CONFIGURED,
    ATHENA_NOT_CONFIGURED,
    AWS_CREDENTIALS_NOT_FOUND
)


def test_error_templates_exist():
    """Test that all required error templates exist"""
    print("Testing error templates exist...")
    
    required_templates = [
        "BEDROCK_NOT_CONFIGURED",
        "BEDROCK_ACCESS_DENIED",
        "BEDROCK_MODEL_NOT_FOUND",
        "ATHENA_NOT_CONFIGURED",
        "ATHENA_QUERY_FAILED",
        "COST_EXPLORER_NOT_CONFIGURED",
        "AWS_CREDENTIALS_NOT_FOUND",
        "AWS_REGION_NOT_SUPPORTED"
    ]
    
    for error_code in required_templates:
        template = get_error_template(error_code)
        assert template is not None, f"Template {error_code} not found"
        assert template.error_code == error_code
        assert template.title, f"Template {error_code} missing title"
        assert template.message, f"Template {error_code} missing message"
        assert template.setup_instructions, f"Template {error_code} missing setup instructions"
        print(f"  ✓ {error_code} template exists and is complete")
    
    print("✅ All error templates exist\n")


def test_bedrock_error_message():
    """Test Bedrock error message includes setup instructions"""
    print("Testing Bedrock error message...")
    
    template = BEDROCK_NOT_CONFIGURED
    
    # Check message content
    assert "AWS Bedrock" in template.title
    assert "demo mode" in template.message.lower()
    
    # Check setup instructions
    assert "aws configure" in template.setup_instructions.lower()
    assert "bedrock" in template.setup_instructions.lower()
    
    # Format message
    formatted = format_error_message(template, include_instructions=True)
    assert "AWS Bedrock" in formatted
    assert "aws configure" in formatted
    
    print("  ✓ Bedrock error message includes clear instructions")
    print("✅ Bedrock error message test passed\n")


def test_athena_error_message():
    """Test Athena error message includes setup instructions"""
    print("Testing Athena error message...")
    
    template = ATHENA_NOT_CONFIGURED
    
    # Check message content
    assert "Athena" in template.title
    assert "demo data" in template.message.lower() or "not configured" in template.message.lower()
    
    # Check setup instructions
    assert "setup-athena.py" in template.setup_instructions or "athena" in template.setup_instructions.lower()
    
    # Format message
    formatted = format_error_message(template, include_instructions=True)
    assert "Athena" in formatted
    
    print("  ✓ Athena error message includes clear instructions")
    print("✅ Athena error message test passed\n")


def test_credentials_error_message():
    """Test AWS credentials error message"""
    print("Testing AWS credentials error message...")
    
    template = AWS_CREDENTIALS_NOT_FOUND
    
    # Check message content
    assert "credentials" in template.title.lower()
    assert "demo mode" in template.message.lower()
    
    # Check setup instructions
    assert "aws configure" in template.setup_instructions.lower()
    assert "AWS_ACCESS_KEY_ID" in template.setup_instructions or "access key" in template.setup_instructions.lower()
    
    print("  ✓ Credentials error message includes setup steps")
    print("✅ Credentials error message test passed\n")


def test_error_response_format():
    """Test error response formatting for API"""
    print("Testing error response formatting...")
    
    # Test with instructions
    response = format_error_response("BEDROCK_NOT_CONFIGURED", include_instructions=True)
    assert response["error"] == "BEDROCK_NOT_CONFIGURED"
    assert "title" in response
    assert "message" in response
    assert "setup_instructions" in response
    print("  ✓ Response includes setup instructions when requested")
    
    # Test without instructions
    response = format_error_response("BEDROCK_NOT_CONFIGURED", include_instructions=False)
    assert response["error"] == "BEDROCK_NOT_CONFIGURED"
    assert "title" in response
    assert "message" in response
    assert "setup_instructions" not in response
    print("  ✓ Response excludes setup instructions when not requested")
    
    # Test unknown error code
    response = format_error_response("UNKNOWN_ERROR_CODE")
    assert response["error"] == "UNKNOWN_ERROR"
    assert "message" in response
    print("  ✓ Unknown error codes handled gracefully")
    
    print("✅ Error response formatting test passed\n")


def test_formatted_message_readability():
    """Test that formatted messages are readable"""
    print("Testing formatted message readability...")
    
    template = BEDROCK_NOT_CONFIGURED
    formatted = format_error_message(template, include_instructions=True)
    
    # Check formatting elements
    assert "╔" in formatted or "=" in formatted, "Message should have visual formatting"
    assert "\n" in formatted, "Message should have line breaks"
    assert len(formatted) > 100, "Message should be substantial"
    
    # Check key sections present
    assert template.title in formatted
    assert template.message in formatted
    assert "aws configure" in formatted.lower()
    
    print("  ✓ Formatted message is well-structured")
    print("  ✓ Message includes title, description, and instructions")
    print("✅ Message readability test passed\n")


def main():
    """Run all tests"""
    print("=" * 70)
    print("Testing Error Message Templates Implementation")
    print("=" * 70)
    print()
    
    try:
        test_error_templates_exist()
        test_bedrock_error_message()
        test_athena_error_message()
        test_credentials_error_message()
        test_error_response_format()
        test_formatted_message_readability()
        
        print("=" * 70)
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        print()
        print("Summary:")
        print("  • All error templates exist and are complete")
        print("  • Error messages include clear setup instructions")
        print("  • Messages are properly formatted for readability")
        print("  • API response format works correctly")
        print()
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
