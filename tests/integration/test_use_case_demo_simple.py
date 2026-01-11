"""
Simple Integration Tests for Use Case Demonstration

This module provides focused integration tests for the cybersecurity
use case demonstration core functionality.
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import sys
import os

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from src.python.use_case_demo.mock_data_scenarios import MockDataGenerator
from src.python.use_case_demo.security_dashboard import SecurityAlertAnalyzer, InteractiveDemoWorkflow


class TestUseCaseDemoSimple(unittest.TestCase):
    """Simple integration tests for use case demonstration."""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_generator = MockDataGenerator()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_mock_data_generation(self):
        """Test mock data generation for all scenarios"""
        scenarios = {
            'apt': self.mock_generator.generate_apt_scenario(12),
            'insider': self.mock_generator.generate_insider_threat_scenario(7),
            'malware': self.mock_generator.generate_malware_outbreak_scenario(6),
            'policy': self.mock_generator.generate_policy_violation_scenario(10)
        }
        
        for scenario_name, scenario_data in scenarios.items():
            # Validate data structure
            self.assertIn('security_events', scenario_data)
            self.assertIn('network_traffic', scenario_data)
            self.assertIn('access_logs', scenario_data)
            
            # Validate data content
            self.assertGreater(len(scenario_data['security_events']), 0)
            
            # Validate event structure
            for event in scenario_data['security_events']:
                self.assertIn('event_id', event)
                self.assertIn('timestamp', event)
                self.assertIn('severity', event)
                self.assertIn('event_type', event)
    
    def test_demo_workflow_scenarios(self):
        """Test all demo workflow scenarios"""
        demo = InteractiveDemoWorkflow()
        
        scenarios = [
            'advanced_persistent_threat',
            'insider_threat',
            'malware_outbreak',
            'policy_violations'
        ]
        
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result = demo.run_demo_scenario(scenario)
                
                # Validate result structure
                self.assertIn('scenario', result)
                self.assertIn('description', result)
                self.assertIn('timeline', result)
                self.assertIn('analysis_results', result)
                self.assertIn('recommendations', result)
                
                # Validate content
                self.assertIsInstance(result['timeline'], list)
                self.assertIsInstance(result['recommendations'], list)
                self.assertGreater(len(result['recommendations']), 0)
    
    def test_security_analyzer_basic_functionality(self):
        """Test basic security analyzer functionality"""
        # Create analyzer with temp directory (will have no data)
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        
        # Generate dashboard data (should handle empty data gracefully)
        dashboard_data = analyzer.generate_dashboard_data()
        
        # Validate structure
        self.assertIn('alerts', dashboard_data)
        self.assertIn('threat_patterns', dashboard_data)
        self.assertIn('metrics', dashboard_data)
        self.assertIn('timestamp', dashboard_data)
        
        # Validate metrics structure
        metrics = dashboard_data['metrics']
        required_metrics = [
            'total_alerts', 'critical_alerts', 'resolved_alerts',
            'false_positives', 'mean_resolution_time', 
            'threat_patterns_detected', 'security_score', 'trend_direction'
        ]
        
        for metric in required_metrics:
            self.assertIn(metric, metrics)
    
    def test_data_file_operations(self):
        """Test data file save and load operations"""
        # Generate test data
        apt_data = self.mock_generator.generate_apt_scenario(6)
        
        # Save data to files
        file_paths = self.mock_generator.save_scenario_data(
            "test_scenario", apt_data, self.temp_dir
        )
        
        # Validate files were created
        for data_type, file_path in file_paths.items():
            self.assertTrue(Path(file_path).exists())
            
            # Validate file content
            with open(file_path, 'r') as f:
                loaded_data = json.load(f)
                self.assertIsInstance(loaded_data, list)
                self.assertEqual(len(loaded_data), len(apt_data[data_type]))
    
    def test_threat_pattern_identification(self):
        """Test threat pattern identification logic"""
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        
        # Create test alerts
        from src.python.use_case_demo.security_dashboard import SecurityAlert
        from datetime import datetime
        
        test_alerts = [
            SecurityAlert(
                alert_id="test_1",
                timestamp=datetime.now(),
                severity="HIGH",
                alert_type="INTRUSION",
                source_ip="192.168.1.1",
                target_ip="10.0.0.1",
                description="Test intrusion",
                threat_indicators=["port_scan"],
                affected_assets=["server1"],
                confidence_score=0.8,
                status="OPEN"
            ),
            SecurityAlert(
                alert_id="test_2",
                timestamp=datetime.now(),
                severity="HIGH",
                alert_type="INTRUSION",
                source_ip="192.168.1.2",
                target_ip="10.0.0.2",
                description="Another test intrusion",
                threat_indicators=["brute_force"],
                affected_assets=["server2"],
                confidence_score=0.9,
                status="OPEN"
            )
        ]
        
        # Test pattern identification
        patterns = analyzer.identify_threat_patterns(test_alerts)
        
        # Should identify at least one pattern (both are HIGH INTRUSION)
        self.assertGreater(len(patterns), 0)
        
        # Validate pattern structure
        for pattern in patterns:
            self.assertTrue(hasattr(pattern, 'pattern_id'))
            self.assertTrue(hasattr(pattern, 'pattern_name'))
            self.assertTrue(hasattr(pattern, 'frequency'))
            self.assertTrue(hasattr(pattern, 'severity_distribution'))
    
    def test_security_metrics_calculation(self):
        """Test security metrics calculation"""
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        
        # Create test alerts with various severities
        from src.python.use_case_demo.security_dashboard import SecurityAlert
        from datetime import datetime
        
        test_alerts = [
            SecurityAlert(
                alert_id="critical_1",
                timestamp=datetime.now(),
                severity="CRITICAL",
                alert_type="MALWARE",
                source_ip="192.168.1.1",
                target_ip="10.0.0.1",
                description="Critical malware",
                threat_indicators=["malware"],
                affected_assets=["server1"],
                confidence_score=0.95,
                status="OPEN"
            ),
            SecurityAlert(
                alert_id="high_1",
                timestamp=datetime.now(),
                severity="HIGH",
                alert_type="INTRUSION",
                source_ip="192.168.1.2",
                target_ip="10.0.0.2",
                description="High severity intrusion",
                threat_indicators=["intrusion"],
                affected_assets=["server2"],
                confidence_score=0.85,
                status="RESOLVED"
            ),
            SecurityAlert(
                alert_id="medium_1",
                timestamp=datetime.now(),
                severity="MEDIUM",
                alert_type="POLICY_VIOLATION",
                source_ip="192.168.1.3",
                target_ip="10.0.0.3",
                description="Policy violation",
                threat_indicators=["policy"],
                affected_assets=["server3"],
                confidence_score=0.7,
                status="FALSE_POSITIVE"
            )
        ]
        
        # Calculate metrics
        metrics = analyzer.calculate_security_metrics(test_alerts)
        
        # Validate metrics
        self.assertEqual(metrics.total_alerts, 3)
        self.assertEqual(metrics.critical_alerts, 1)
        self.assertEqual(metrics.resolved_alerts, 1)
        self.assertEqual(metrics.false_positives, 1)
        self.assertGreaterEqual(metrics.security_score, 0)
        self.assertLessEqual(metrics.security_score, 100)
        self.assertIn(metrics.trend_direction, ['IMPROVING', 'STABLE', 'DEGRADING'])


class TestUseCaseDemoErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_empty_data_handling(self):
        """Test handling of empty data"""
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        
        # Should handle empty data gracefully
        dashboard_data = analyzer.generate_dashboard_data()
        
        self.assertEqual(dashboard_data['metrics']['total_alerts'], 0)
        self.assertEqual(len(dashboard_data['alerts']), 0)
        self.assertEqual(len(dashboard_data['threat_patterns']), 0)
    
    def test_invalid_scenario_handling(self):
        """Test handling of invalid scenario names"""
        demo = InteractiveDemoWorkflow()
        
        with self.assertRaises(ValueError):
            demo.run_demo_scenario('invalid_scenario_name')
    
    def test_malformed_data_handling(self):
        """Test handling of malformed data files"""
        # Create malformed JSON file
        malformed_file = Path(self.temp_dir) / "security_events.json"
        with open(malformed_file, 'w') as f:
            f.write("invalid json content")
        
        # Analyzer should handle this gracefully
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        dashboard_data = analyzer.generate_dashboard_data()
        
        # Should return empty results without crashing
        self.assertEqual(dashboard_data['metrics']['total_alerts'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)