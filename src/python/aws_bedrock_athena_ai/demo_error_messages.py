"""
Demo script to showcase error message templates.

This script displays all error message templates to demonstrate
the clear, actionable error messages with setup instructions.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aws_bedrock_athena_ai.api.error_messages import (
    get_error_template,
    format_error_message,
    BEDROCK_NOT_CONFIGURED,
    BEDROCK_ACCESS_DENIED,
    ATHENA_NOT_CONFIGURED,
    AWS_CREDENTIALS_NOT_FOUND
)


def demo_bedrock_error():
    """Demonstrate Bedrock error message"""
    print("\n" + "=" * 80)
    print("EXAMPLE 1: AWS Bedrock Not Configured")
    print("=" * 80)
    
    template = BEDROCK_NOT_CONFIGURED
    message = format_error_message(template, include_instructions=True)
    print(message)


def demo_bedrock_access_denied():
    """Demonstrate Bedrock access denied error"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: AWS Bedrock Access Denied")
    print("=" * 80)
    
    template = BEDROCK_ACCESS_DENIED
    message = format_error_message(template, include_instructions=True)
    print(message)


def demo_athena_error():
    """Demonstrate Athena error message"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: AWS Athena Not Configured")
    print("=" * 80)
    
    template = ATHENA_NOT_CONFIGURED
    message = format_error_message(template, include_instructions=True)
    print(message)


def demo_credentials_error():
    """Demonstrate credentials error message"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: AWS Credentials Not Found")
    print("=" * 80)
    
    template = AWS_CREDENTIALS_NOT_FOUND
    message = format_error_message(template, include_instructions=True)
    print(message)


def demo_all_error_codes():
    """List all available error codes"""
    print("\n" + "=" * 80)
    print("ALL AVAILABLE ERROR TEMPLATES")
    print("=" * 80)
    print()
    
    error_codes = [
        "BEDROCK_NOT_CONFIGURED",
        "BEDROCK_ACCESS_DENIED",
        "BEDROCK_MODEL_NOT_FOUND",
        "ATHENA_NOT_CONFIGURED",
        "ATHENA_QUERY_FAILED",
        "COST_EXPLORER_NOT_CONFIGURED",
        "AWS_CREDENTIALS_NOT_FOUND",
        "AWS_REGION_NOT_SUPPORTED"
    ]
    
    for code in error_codes:
        template = get_error_template(code)
        if template:
            print(f"✓ {code}")
            print(f"  Title: {template.title}")
            print(f"  Message: {template.message[:80]}...")
            print()


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("ERROR MESSAGE TEMPLATES DEMONSTRATION")
    print("=" * 80)
    print()
    print("This demo shows the clear, actionable error messages that users")
    print("will see when AWS services are not configured.")
    print()
    print("Each error message includes:")
    print("  • Clear title and description")
    print("  • Explanation of what went wrong")
    print("  • Step-by-step setup instructions")
    print("  • Links to official documentation")
    print()
    
    # Show all available error codes
    demo_all_error_codes()
    
    # Show detailed examples
    demo_bedrock_error()
    demo_bedrock_access_denied()
    demo_athena_error()
    demo_credentials_error()
    
    print("\n" + "=" * 80)
    print("BENEFITS")
    print("=" * 80)
    print()
    print("✓ Users understand what went wrong")
    print("✓ Clear steps to fix the issue")
    print("✓ No cryptic error messages")
    print("✓ Application continues in demo mode")
    print("✓ Links to official documentation")
    print("✓ Copy-paste ready commands")
    print()
    print("=" * 80)
    print()


if __name__ == "__main__":
    main()
