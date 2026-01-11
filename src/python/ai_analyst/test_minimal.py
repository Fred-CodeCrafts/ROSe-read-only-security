"""
Minimal test to verify basic functionality without heavy dependencies
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that we can import the basic models"""
    try:
        from src.python.ai_analyst.models import (
            SeverityLevel, 
            SecurityEventType, 
            SecurityFinding,
            SecurityAssessment
        )
        print("[+] Successfully imported models")
        return True
    except ImportError as e:
        print(f"[x] Import failed: {e}")
        return False

def test_model_creation():
    """Test that we can create model instances"""
    try:
        from src.python.ai_analyst.models import SecurityFinding, SeverityLevel, SecurityEventType
        from datetime import datetime
        
        finding = SecurityFinding(
            id="test-001",
            type=SecurityEventType.SUSPICIOUS_PATTERN,
            severity=SeverityLevel.MEDIUM,
            title="Test Finding",
            description="This is a test security finding",
            confidence=0.8
        )
        
        print(f"[+] Created SecurityFinding: {finding.title}")
        return True
    except Exception as e:
        print(f"[x] Model creation failed: {e}")
        return False

if __name__ == "__main__":
    print("Running minimal tests...")
    
    success = True
    success &= test_imports()
    success &= test_model_creation()
    
    if success:
        print("\n[+] Minimal tests passed!")
    else:
        print("\n[x] Some tests failed!")