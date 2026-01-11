"""
Basic test to verify OSS Security Analyst implementation
"""

import os
import tempfile
from pathlib import Path
from src.python.ai_analyst import OSSSecurityAnalyst


def test_basic_initialization():
    """Test that OSSSecurityAnalyst can be initialized"""
    try:
        # Create temporary directories for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            analyst = OSSSecurityAnalyst(
                ollama_endpoint="http://localhost:11434",
                analysis_db_path=os.path.join(temp_dir, "test_analysis.db"),
                vector_db_path=os.path.join(temp_dir, "test_vector_db")
            )
            print("✓ OSSSecurityAnalyst initialized successfully")
            return True
    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        return False


def test_basic_repo_analysis():
    """Test basic repository analysis functionality"""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a simple test repository structure
            test_repo = Path(temp_dir) / "test_repo"
            test_repo.mkdir()
            
            # Create some test files
            (test_repo / "README.md").write_text("# Test Repository")
            (test_repo / "requirements.txt").write_text("requests==2.31.0\nflask==2.3.0")
            (test_repo / "config.yaml").write_text("database:\n  host: localhost")
            
            # Initialize analyst
            analyst = OSSSecurityAnalyst(
                analysis_db_path=os.path.join(temp_dir, "test_analysis.db"),
                vector_db_path=os.path.join(temp_dir, "test_vector_db")
            )
            
            # Perform analysis (this will work even if Ollama is not available)
            report = analyst.analyze_repository(str(test_repo))
            
            print(f"✓ Repository analysis completed")
            print(f"  - Files analyzed: {report.repo_structure.get('total_files', 0)}")
            print(f"  - Security findings: {len(report.security_findings)}")
            print(f"  - Recommendations: {len(report.recommendations)}")
            
            return True
            
    except Exception as e:
        print(f"✗ Repository analysis failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing OSS Security Analyst...")
    
    success = True
    success &= test_basic_initialization()
    success &= test_basic_repo_analysis()
    
    if success:
        print("\n✓ All basic tests passed!")
    else:
        print("\n✗ Some tests failed!")