"""
Simple test script for the use case demonstration.
"""

import sys
import os
import json
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.append(str(project_root))

try:
    from src.python.use_case_demo.security_dashboard import SecurityAlertAnalyzer, InteractiveDemoWorkflow
    from src.python.use_case_demo.security_visualizer import SecurityMetricsVisualizer
    from src.python.use_case_demo.mock_data_scenarios import MockDataGenerator
    
    print("✅ All imports successful")
    
    # Test basic functionality
    print("\n=== Testing Security Alert Analyzer ===")
    analyzer = SecurityAlertAnalyzer()
    dashboard_data = analyzer.generate_dashboard_data()
    
    print(f"Dashboard data generated:")
    print(f"- Total alerts: {dashboard_data['metrics']['total_alerts']}")
    print(f"- Security score: {dashboard_data['metrics']['security_score']:.1f}")
    print(f"- Threat patterns: {dashboard_data['metrics']['threat_patterns_detected']}")
    
    print("\n=== Testing Demo Workflow ===")
    demo = InteractiveDemoWorkflow()
    scenario_result = demo.run_demo_scenario('advanced_persistent_threat')
    print(f"APT scenario completed: {scenario_result['scenario']}")
    print(f"Recommendations: {len(scenario_result['recommendations'])}")
    
    print("\n=== Testing Mock Data Generator ===")
    generator = MockDataGenerator()
    apt_data = generator.generate_apt_scenario(24)
    print(f"APT scenario data generated:")
    print(f"- Security events: {len(apt_data['security_events'])}")
    print(f"- Network traffic: {len(apt_data['network_traffic'])}")
    print(f"- Access logs: {len(apt_data['access_logs'])}")
    
    print("\n=== Testing Visualizer (without matplotlib) ===")
    try:
        visualizer = SecurityMetricsVisualizer()
        print("✅ Visualizer initialized successfully")
    except ImportError as e:
        print(f"⚠️ Visualizer requires matplotlib: {e}")
    
    print("\n🎉 All tests completed successfully!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Some platform components may not be available")
except Exception as e:
    print(f"❌ Test error: {e}")