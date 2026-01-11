"""
Simple test for the use case demonstration components only.
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.append(str(project_root))

def test_basic_imports():
    """Test basic imports without platform dependencies"""
    try:
        from src.python.use_case_demo.mock_data_scenarios import MockDataGenerator
        print("✅ MockDataGenerator imported successfully")
        
        # Test mock data generation
        generator = MockDataGenerator()
        apt_data = generator.generate_apt_scenario(24)
        print(f"✅ APT scenario generated: {len(apt_data['security_events'])} events")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_dashboard_basic():
    """Test basic dashboard functionality without external dependencies"""
    try:
        # Import just the classes we need
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
        
        # Create a minimal test
        from src.python.use_case_demo.security_dashboard import SecurityAlert, ThreatPattern, SecurityMetrics
        
        # Test data structures
        alert = SecurityAlert(
            alert_id="test_001",
            timestamp="2024-01-01T10:00:00",
            severity="HIGH",
            alert_type="INTRUSION",
            source_ip="192.168.1.100",
            target_ip="10.0.0.50",
            description="Test alert",
            threat_indicators=["test_indicator"],
            affected_assets=["test_asset"],
            confidence_score=0.9,
            status="OPEN"
        )
        
        print("✅ SecurityAlert created successfully")
        print(f"   Alert ID: {alert.alert_id}")
        print(f"   Severity: {alert.severity}")
        
        return True
    except Exception as e:
        print(f"❌ Dashboard test error: {e}")
        return False

def main():
    """Run all tests"""
    print("=== Use Case Demo Simple Tests ===")
    
    success = True
    
    print("\n1. Testing mock data generation...")
    success &= test_basic_imports()
    
    print("\n2. Testing dashboard data structures...")
    success &= test_dashboard_basic()
    
    if success:
        print("\n🎉 All basic tests passed!")
    else:
        print("\n❌ Some tests failed")
    
    return success

if __name__ == "__main__":
    main()