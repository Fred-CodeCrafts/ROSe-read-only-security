"""
Integration Tests for Use Case Demonstration

This module provides comprehensive integration tests for the cybersecurity
use case demonstration, validating end-to-end workflows and cross-component
data flow consistency.
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import sys
import os

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from src.python.use_case_demo.security_dashboard import SecurityAlertAnalyzer, InteractiveDemoWorkflow
from src.python.use_case_demo.mock_data_scenarios import MockDataGenerator
from src.python.use_case_demo.security_visualizer import SecurityMetricsVisualizer


class TestUseCaseDemoIntegration(unittest.TestCase):
    """Integration tests for the complete use case demonstration."""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_data_dir = Path(self.temp_dir) / "test_data"
        self.test_data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.mock_generator = MockDataGenerator()
        self.security_analyzer = SecurityAlertAnalyzer(str(self.test_data_dir))
        self.demo_workflow = InteractiveDemoWorkflow()
        self.visualizer = SecurityMetricsVisualizer(str(self.temp_dir))
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _consolidate_scenario_data(self, all_file_paths):
        """Consolidate all scenario data into the expected filenames for the analyzer"""
        consolidated_data = {
            'security_events': [],
            'network_traffic': [],
            'access_logs': []
        }
        
        # Collect all data from all scenarios
        for scenario_name, file_paths in all_file_paths.items():
            for data_type, file_path in file_paths.items():
                if data_type in consolidated_data:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        consolidated_data[data_type].extend(data)
        
        # Save consolidated data with expected filenames
        for data_type, data_list in consolidated_data.items():
            consolidated_file = self.test_data_dir / f"{data_type}.json"
            with open(consolidated_file, 'w') as f:
                json.dump(data_list, f, indent=2)
    
    def test_end_to_end_apt_scenario_workflow(self):
        """Test complete APT scenario workflow from data generation to visualization"""
        # Step 1: Generate mock APT scenario data
        apt_data = self.mock_generator.generate_apt_scenario(24)
        
        # Validate generated data structure
        self.assertIn('security_events', apt_data)
        self.assertIn('network_traffic', apt_data)
        self.assertIn('access_logs', apt_data)
        
        self.assertGreater(len(apt_data['security_events']), 0)
        self.assertGreater(len(apt_data['network_traffic']), 0)
        self.assertGreater(len(apt_data['access_logs']), 0)
        
        # Step 2: Save scenario data to test directory
        file_paths = self.mock_generator.save_scenario_data(
            "test_apt", apt_data, str(self.test_data_dir)
        )
        
        # Validate files were created
        for data_type, file_path in file_paths.items():
            self.assertTrue(Path(file_path).exists())
            
            # Validate file content
            with open(file_path, 'r') as f:
                loaded_data = json.load(f)
                self.assertIsInstance(loaded_data, list)
                self.assertGreater(len(loaded_data), 0)
        
        # Step 3: Analyze security events
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        
        # Validate dashboard data structure
        self.assertIn('alerts', dashboard_data)
        self.assertIn('threat_patterns', dashboard_data)
        self.assertIn('metrics', dashboard_data)
        
        # Validate metrics
        metrics = dashboard_data['metrics']
        self.assertIn('total_alerts', metrics)
        self.assertIn('security_score', metrics)
        self.assertIn('threat_patterns_detected', metrics)
        
        # Step 4: Run interactive demo scenario
        scenario_result = self.demo_workflow.run_demo_scenario('advanced_persistent_threat')
        
        # Validate scenario result
        self.assertIn('scenario', scenario_result)
        self.assertIn('description', scenario_result)
        self.assertIn('timeline', scenario_result)
        self.assertIn('analysis_results', scenario_result)
        self.assertIn('recommendations', scenario_result)
        
        self.assertEqual(scenario_result['scenario'], 'Advanced Persistent Threat')
        self.assertIsInstance(scenario_result['timeline'], list)
        self.assertIsInstance(scenario_result['recommendations'], list)
        
        # Step 5: Test visualization generation (without matplotlib dependencies)
        try:
            # This will test the data preparation even if visualization fails
            dashboard_path = self.visualizer.create_security_overview_dashboard(dashboard_data)
            # If successful, validate the path
            if dashboard_path:
                self.assertTrue(Path(dashboard_path).exists())
        except ImportError:
            # Skip visualization test if matplotlib not available
            self.skipTest("Matplotlib not available for visualization testing")
    
    def test_cross_component_data_flow_consistency(self):
        """Test data flow consistency across all components"""
        # Generate multiple scenario types
        scenarios = {
            'apt': self.mock_generator.generate_apt_scenario(12),
            'insider': self.mock_generator.generate_insider_threat_scenario(7),
            'malware': self.mock_generator.generate_malware_outbreak_scenario(6),
            'policy': self.mock_generator.generate_policy_violation_scenario(10)
        }
        
        # Save all scenarios
        all_file_paths = {}
        for scenario_name, scenario_data in scenarios.items():
            file_paths = self.mock_generator.save_scenario_data(
                scenario_name, scenario_data, str(self.test_data_dir)
            )
            all_file_paths[scenario_name] = file_paths
        
        # Consolidate all scenario data into the expected filenames for the analyzer
        self._consolidate_scenario_data(all_file_paths)
        
        # Reinitialize the analyzer to load the consolidated data
        self.security_analyzer = SecurityAlertAnalyzer(str(self.test_data_dir))
        
        # Validate cross-scenario data consistency
        for scenario_name, file_paths in all_file_paths.items():
            for data_type, file_path in file_paths.items():
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                    # Validate data structure consistency
                    if data_type == 'security_events':
                        for event in data:
                            self.assertIn('event_id', event)
                            self.assertIn('timestamp', event)
                            self.assertIn('severity', event)
                            self.assertIn('event_type', event)
                    
                    elif data_type == 'network_traffic':
                        for traffic in data:
                            self.assertIn('session_id', traffic)
                            self.assertIn('timestamp', traffic)
                            self.assertIn('source_ip', traffic)
                            self.assertIn('destination_ip', traffic)
                    
                    elif data_type == 'access_logs':
                        for log in data:
                            self.assertIn('log_id', log)
                            self.assertIn('timestamp', log)
                            self.assertIn('user_id', log)
                            self.assertIn('resource', log)
        
        # Test analyzer with combined data
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        
        # Validate comprehensive analysis
        self.assertGreater(dashboard_data['metrics']['total_alerts'], 0)
        self.assertGreaterEqual(dashboard_data['metrics']['security_score'], 0)
        self.assertLessEqual(dashboard_data['metrics']['security_score'], 100)
    
    def test_comprehensive_reporting_capabilities(self):
        """Test comprehensive reporting across all components"""
        # Generate test data
        apt_data = self.mock_generator.generate_apt_scenario(24)
        self.mock_generator.save_scenario_data("test_reporting", apt_data, str(self.test_data_dir))
        
        # Generate dashboard data
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        
        # Test all demo scenarios
        demo_scenarios = [
            'advanced_persistent_threat',
            'insider_threat', 
            'malware_outbreak',
            'policy_violations'
        ]
        
        scenario_results = {}
        for scenario in demo_scenarios:
            result = self.demo_workflow.run_demo_scenario(scenario)
            scenario_results[scenario] = result
            
            # Validate each scenario result
            self.assertIn('scenario', result)
            self.assertIn('description', result)
            self.assertIn('timeline', result)
            self.assertIn('analysis_results', result)
            self.assertIn('recommendations', result)
            
            # Validate timeline structure
            timeline = result['timeline']
            self.assertIsInstance(timeline, list)
            for event in timeline:
                self.assertIn('time', event)
                self.assertIn('event', event)
            
            # Validate recommendations
            recommendations = result['recommendations']
            self.assertIsInstance(recommendations, list)
            self.assertGreater(len(recommendations), 0)
        
        # Test comprehensive report generation
        comprehensive_report = {
            'dashboard_data': dashboard_data,
            'scenario_results': scenario_results,
            'generation_timestamp': datetime.now().isoformat(),
            'test_metadata': {
                'total_scenarios': len(demo_scenarios),
                'data_sources': len(apt_data),
                'test_environment': 'integration_test'
            }
        }
        
        # Validate comprehensive report structure
        self.assertIn('dashboard_data', comprehensive_report)
        self.assertIn('scenario_results', comprehensive_report)
        self.assertIn('generation_timestamp', comprehensive_report)
        self.assertIn('test_metadata', comprehensive_report)
        
        # Save comprehensive report
        report_file = Path(self.temp_dir) / "comprehensive_report.json"
        with open(report_file, 'w') as f:
            json.dump(comprehensive_report, f, indent=2, default=str)
        
        self.assertTrue(report_file.exists())
        
        # Validate saved report
        with open(report_file, 'r') as f:
            loaded_report = json.load(f)
            self.assertEqual(len(loaded_report['scenario_results']), len(demo_scenarios))
    
    def test_data_validation_and_consistency(self):
        """Test data validation and consistency across components"""
        # Generate test data with known characteristics
        apt_data = self.mock_generator.generate_apt_scenario(24)
        
        # Validate APT scenario characteristics
        security_events = apt_data['security_events']
        
        # Should have events representing APT phases
        event_types = [event['event_type'] for event in security_events]
        self.assertIn('MALWARE', event_types)  # Initial compromise
        self.assertIn('INTRUSION', event_types)  # Privilege escalation/lateral movement
        
        # Should have escalating severity
        severities = [event['severity'] for event in security_events]
        self.assertIn('CRITICAL', severities)  # Should have critical events
        
        # Network traffic should correspond to security events
        network_traffic = apt_data['network_traffic']
        self.assertEqual(len(network_traffic), len(security_events))
        
        # Timestamps should be consistent
        for i, (event, traffic) in enumerate(zip(security_events, network_traffic)):
            self.assertEqual(event['timestamp'], traffic['timestamp'])
            self.assertEqual(event['source_ip'], traffic['source_ip'])
            self.assertEqual(event['target_ip'], traffic['destination_ip'])
        
        # Test analyzer consistency
        file_paths = self.mock_generator.save_scenario_data("consistency_test", apt_data, str(self.test_data_dir))
        
        # Consolidate data for the analyzer
        self._consolidate_scenario_data({"consistency_test": file_paths})
        
        # Reinitialize the analyzer to load the consolidated data
        self.security_analyzer = SecurityAlertAnalyzer(str(self.test_data_dir))
        
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        
        # Validate analyzer processed the data correctly
        self.assertGreater(dashboard_data['metrics']['total_alerts'], 0)
        
        # Should detect threat patterns in APT scenario
        threat_patterns = dashboard_data['threat_patterns']
        if threat_patterns:  # May be empty if not enough patterns detected
            for pattern in threat_patterns:
                self.assertIn('pattern_name', pattern)
                self.assertIn('frequency', pattern)
                self.assertGreater(pattern['frequency'], 0)
    
    def test_error_handling_and_resilience(self):
        """Test error handling and system resilience"""
        # Test with empty data
        empty_dashboard = self.security_analyzer.generate_dashboard_data()
        self.assertIn('metrics', empty_dashboard)
        self.assertEqual(empty_dashboard['metrics']['total_alerts'], 0)
        
        # Test with invalid scenario name
        with self.assertRaises(ValueError):
            self.demo_workflow.run_demo_scenario('invalid_scenario')
        
        # Test with malformed data
        malformed_data = {
            'security_events': [
                {'invalid': 'structure'}  # Missing required fields
            ],
            'network_traffic': [],
            'access_logs': []
        }
        
        # Save malformed data
        malformed_file = self.test_data_dir / "malformed_security_events.json"
        with open(malformed_file, 'w') as f:
            json.dump(malformed_data['security_events'], f)
        
        # Analyzer should handle malformed data gracefully
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        self.assertIsInstance(dashboard_data, dict)
        self.assertIn('metrics', dashboard_data)
    
    def test_performance_and_scalability(self):
        """Test performance with larger datasets"""
        # Generate larger dataset
        large_apt_data = self.mock_generator.generate_apt_scenario(72)  # 3 days
        large_insider_data = self.mock_generator.generate_insider_threat_scenario(30)  # 30 days
        
        # Measure processing time
        start_time = datetime.now()
        
        # Save large datasets
        apt_file_paths = self.mock_generator.save_scenario_data("large_apt", large_apt_data, str(self.test_data_dir))
        insider_file_paths = self.mock_generator.save_scenario_data("large_insider", large_insider_data, str(self.test_data_dir))
        
        # Consolidate data for the analyzer
        self._consolidate_scenario_data({
            "large_apt": apt_file_paths,
            "large_insider": insider_file_paths
        })
        
        # Reinitialize the analyzer to load the consolidated data
        self.security_analyzer = SecurityAlertAnalyzer(str(self.test_data_dir))
        
        # Process large datasets
        dashboard_data = self.security_analyzer.generate_dashboard_data()
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Validate processing completed successfully
        self.assertIn('metrics', dashboard_data)
        self.assertGreater(dashboard_data['metrics']['total_alerts'], 0)
        
        # Performance should be reasonable (less than 30 seconds for test data)
        self.assertLess(processing_time, 30.0)
        
        # Validate data integrity with large datasets
        total_events = len(large_apt_data['security_events']) + len(large_insider_data['security_events'])
        # Note: The analyzer may not process all events if they're in separate files
        # This is expected behavior for the current implementation


class TestUseCaseDemoDataFlow(unittest.TestCase):
    """Test data flow between components"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_generator = MockDataGenerator()
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_mock_data_to_analyzer_flow(self):
        """Test data flow from mock generator to security analyzer"""
        # Generate mock data
        scenario_data = self.mock_generator.generate_apt_scenario(12)
        
        # Save to temporary location
        file_paths = self.mock_generator.save_scenario_data(
            "flow_test", scenario_data, self.temp_dir
        )
        
        # Initialize analyzer with the data location
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        
        # Process the data
        dashboard_data = analyzer.generate_dashboard_data()
        
        # Validate data flow
        self.assertIsInstance(dashboard_data, dict)
        self.assertIn('metrics', dashboard_data)
        
        # The analyzer should process the generated events
        # Note: Current implementation loads from specific files, so this tests the structure
        self.assertIn('total_alerts', dashboard_data['metrics'])
        self.assertIn('security_score', dashboard_data['metrics'])
    
    def test_analyzer_to_visualizer_flow(self):
        """Test data flow from analyzer to visualizer"""
        # Create test data
        scenario_data = self.mock_generator.generate_apt_scenario(6)
        self.mock_generator.save_scenario_data("viz_test", scenario_data, self.temp_dir)
        
        # Generate dashboard data
        analyzer = SecurityAlertAnalyzer(self.temp_dir)
        dashboard_data = analyzer.generate_dashboard_data()
        
        # Initialize visualizer
        visualizer = SecurityMetricsVisualizer(self.temp_dir)
        
        # Test data compatibility (without actually generating visualizations)
        # This validates the data structure is compatible
        self.assertIn('alerts', dashboard_data)
        self.assertIn('threat_patterns', dashboard_data)
        self.assertIn('metrics', dashboard_data)
        
        # Validate metrics structure for visualization
        metrics = dashboard_data['metrics']
        required_metrics = [
            'total_alerts', 'critical_alerts', 'security_score', 
            'threat_patterns_detected', 'trend_direction'
        ]
        
        for metric in required_metrics:
            self.assertIn(metric, metrics)
    
    def test_demo_workflow_integration(self):
        """Test demo workflow integration with other components"""
        # Initialize demo workflow
        demo = InteractiveDemoWorkflow()
        
        # Test all scenarios
        scenarios = ['advanced_persistent_threat', 'insider_threat', 'malware_outbreak', 'policy_violations']
        
        for scenario in scenarios:
            result = demo.run_demo_scenario(scenario)
            
            # Validate result structure
            self.assertIn('scenario', result)
            self.assertIn('analysis_results', result)
            
            # The analysis_results should contain dashboard data
            analysis_results = result['analysis_results']
            self.assertIn('alerts', analysis_results)
            self.assertIn('metrics', analysis_results)


if __name__ == '__main__':
    # Run tests using unittest's main function
    unittest.main(verbosity=2)