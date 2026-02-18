#!/usr/bin/env python3
"""
Test runner script that sets up the proper Python path for running tests.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to Python path so imports work correctly
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

# Now run pytest
import pytest

if __name__ == "__main__":
    # Run pytest with the tests directory
    exit_code = pytest.main([
        "tests/",
        "-v",
        "--tb=short",
        "--disable-warnings"
    ])
    sys.exit(exit_code)