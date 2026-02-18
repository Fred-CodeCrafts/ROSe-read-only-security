#!/usr/bin/env python3
"""
Interactive test for chat command - simulates user input
"""

import sys
import os
from pathlib import Path
from io import StringIO

# Add src/python to path
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

def test_chat_with_simulated_input():
    """Test chat command with simulated user input"""
    print("Testing chat command with simulated input...")
    print("=" * 70)
    
    # Simulate user input
    simulated_input = "What are our top security risks?\nexit\n"
    
    # Replace stdin with simulated input
    old_stdin = sys.stdin
    sys.stdin = StringIO(simulated_input)
    
    try:
        from aws_bedrock_athena_ai.cli import cmd_chat
        
        # Run chat command
        result = cmd_chat()
        
        print("\n" + "=" * 70)
        print(f"✅ Chat command completed with exit code: {result}")
        return result
        
    except Exception as e:
        print(f"\n❌ Error running chat command: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Restore stdin
        sys.stdin = old_stdin


if __name__ == "__main__":
    sys.exit(test_chat_with_simulated_input())
