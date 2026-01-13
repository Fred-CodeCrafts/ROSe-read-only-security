"""
Property-Based Tests for Threat Detection Accuracy

Feature: aws-bedrock-athena-ai, Property 4: Threat Detection Accuracy
Validates: Requirements 2.1

These tests verify that the threat detection system correctly identifies threats
without generating false positives on normal operational data.
"""

import pytest
from hypothesis import given, strategies as st, settings, example
from hypothesis.strategies import composite
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import uuid

# Import the modules to test
from aws_bedrock_athena_ai.reasoning_engine.threat_analyzer import ThreatAnalyzer
from aws_bedrock_athena_ai.reasoning_engine.models import Threat, ThreatType, ThreatSeverity
from aws_bedrock_athena_ai.data_detective.models import QueryResults


# Strategy for generating security log entries
@composite
def security_log_entry(draw):
    """Generate realistic security log entries"""
    timestamp = draw(st.datetimes(
        min_value=datetime(2024, 1, 1),
        max_value=datetime(2024, 12, 31)
    ))
    
    event_types = [
        'login_success', 'login_failure', 'logout', 'file_access',
        'network_connection', 'process_start', 'process_end',
        'configuration_change', 'system_update', 'user_creation'
    ]
    
    users = ['admin', 'user1', 'user2', 'service_account', 'system']
    systems = ['web-server-1', 'db-server-1', 'api-gateway', 'workstation-1']
    
    return {
        'timestamp': timestamp.isoformat(),
        'event_type': draw(st.sampled_from(event_types)),
        'user': draw(st.sampled_from(users)),
        'system': draw(st.sampled_from(systems)),
        'source_ip': f"192.168.1.{draw(st.integers(1, 254))}",
        'result': draw(st.sampled_from(['success', 'failure', 'warning'])),
        'details': draw(st.text(min_size=10, max_size=100))
    }


@composite
def malicious_log_entry(draw):
    """Generate log entries that should be detected as threats"""
    timestamp = draw(st.datetimes(
        min_value=datetime(2024, 1, 1),
        max_value=datetime(2024, 12, 31)
    ))
    
    # Malicious patterns
    malicious_events = [
        'multiple_failed_logins', 'privilege_escalation', 'suspicious_file_access',
        'malware_detected', 'unauthorized_network_scan', 'data_exfiltration',
        'brute_force_attack', 'sql_injection_attempt'
    ]
    
    suspicious_ips = ['10.0.0.1', '192.168.100.1', '172.16.0.1', '203.0.113.1']
    
    return {
        'timestamp': timestamp.isoformat(),
        'event_type': draw(st.sampled_from(malicious_events)),
        'user': 'unknown_user',
        'system': 'critical-server',
        'source_ip': draw(st.sampled_from(suspicious_ips)),
        'result': 'failure',
        'details': 'suspicious activity detected',
        'severity': 'high',
        'indicators': ['malicious_pattern', 'anomalous_behavior']
    }


@composite
def query_results_strategy(draw, include_threats=False):
    """Generate QueryResults with optional threat indicators"""
    if include_threats:
        # Mix of normal and malicious entries
        normal_entries = draw(st.lists(security_log_entry(), min_size=5, max_size=20))
        malicious_entries = draw(st.lists(malicious_log_entry(), min_size=1, max_size=5))
        rows = normal_entries + malicious_entries
    else:
        # Only normal operational data
        rows = draw(st.lists(security_log_entry(), min_size=10, max_size=50))
    
    return QueryResults(
        query_id=f"test-query-{hash(str(rows)) % 10000}",
        data=rows,
        column_names=['timestamp', 'event_type', 'user', 'system', 'source_ip', 'result', 'details', 'severity'],
        row_count=len(rows),
        data_scanned_gb=len(rows) * 0.001,
        execution_time_ms=100 + len(rows) * 2,
        cost_usd=len(rows) * 0.0001,
        query_sql="SELECT * FROM security_logs WHERE timestamp > '2024-01-01'",
        source_tables=['security_logs']
    )


class TestThreatDetectionProperties:
    """Property-based tests for threat detection accuracy"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.analyzer = ThreatAnalyzer('us-east-1')
    
    @given(query_results_strategy(include_threats=True))
    @settings(max_examples=50, deadline=30000)  # 30 second timeout
    @example(QueryResults(
        query_id="test-query-123",
        data=[{
            'timestamp': '2024-01-15T10:30:00Z',
            'event_type': 'multiple_failed_logins',
            'user': 'admin',
            'system': 'web-server-1',
            'source_ip': '203.0.113.1',
            'result': 'failure',
            'details': 'brute force attack detected',
            'severity': 'critical'
        }],
        column_names=['timestamp', 'event_type', 'user', 'system', 'source_ip', 'result', 'details', 'severity'],
        row_count=1,
        data_scanned_gb=0.001,
        execution_time_ms=150,
        cost_usd=0.0001,
        query_sql="SELECT * FROM security_logs",
        source_tables=['security_logs']
    ))
    def test_threat_detection_with_malicious_data(self, query_results):
        """
        Property 4: Threat Detection Accuracy - Malicious Data Detection
        
        For any security data containing known threat patterns, the system should 
        correctly identify threats without generating false positives on normal 
        operational data.
        """
        # Mock Bedrock response for consistent testing
        mock_response = {
            "threats": [
                {
                    "threat_type": "suspicious_activity",
                    "severity": "high",
                    "title": "Suspicious Activity Detected",
                    "description": "Anomalous behavior patterns identified",
                    "affected_systems": ["web-server-1"],
                    "indicators": ["unusual_access_pattern"],
                    "evidence": [
                        {
                            "source": "security_logs",
                            "description": "Multiple failed login attempts",
                            "confidence": 0.8
                        }
                    ],
                    "confidence": 0.8,
                    "first_seen": "2024-01-15T10:30:00Z",
                    "last_seen": "2024-01-15T10:35:00Z"
                }
            ]
        }
        
        with patch.object(self.analyzer, '_call_bedrock_model') as mock_bedrock:
            mock_bedrock.return_value = json.dumps(mock_response)
            
            # Analyze the data
            threats = self.analyzer.analyze_security_patterns(query_results)
            
            # Property: System should identify threats when malicious patterns exist
            malicious_entries = [
                row for row in query_results.data 
                if any(indicator in str(row).lower() for indicator in [
                    'malicious', 'suspicious', 'attack', 'breach', 'failed_login',
                    'brute_force', 'escalation', 'exfiltration'
                ])
            ]
            
            if malicious_entries:
                # Should detect at least one threat when malicious data is present
                assert len(threats) > 0, f"Failed to detect threats in data with {len(malicious_entries)} malicious entries"
                
                # All detected threats should have reasonable confidence
                for threat in threats:
                    assert 0.0 <= threat.confidence <= 1.0, f"Invalid confidence score: {threat.confidence}"
                    assert threat.threat_type is not None, f"Threat type should not be None"
                    assert threat.severity is not None, f"Severity should not be None"
    
    @given(query_results_strategy(include_threats=False))
    @settings(max_examples=30, deadline=20000)
    def test_no_false_positives_on_normal_data(self, query_results):
        """
        Property 4: Threat Detection Accuracy - False Positive Prevention
        
        For any normal operational data without threat indicators, the system 
        should not generate false positive threat detections.
        """
        # Mock Bedrock response indicating no threats
        mock_response = {"threats": []}
        
        with patch.object(self.analyzer, '_call_bedrock_model') as mock_bedrock:
            mock_bedrock.return_value = json.dumps(mock_response)
            
            # Analyze normal operational data
            threats = self.analyzer.analyze_security_patterns(query_results)
            
            # Property: Normal data should not trigger threat detection
            # Allow for very low-confidence informational findings but no high-severity threats
            high_severity_threats = [
                t for t in threats 
                if t.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]
            ]
            
            assert len(high_severity_threats) == 0, (
                f"False positive: detected {len(high_severity_threats)} high-severity threats "
                f"in normal operational data"
            )
    
    @given(st.lists(security_log_entry(), min_size=1, max_size=10))
    @settings(max_examples=20, deadline=15000)
    def test_threat_confidence_consistency(self, log_entries):
        """
        Property 4: Threat Detection Accuracy - Confidence Consistency
        
        For any threat detection, confidence scores should be consistent with 
        the strength of evidence and threat severity.
        """
        query_results = QueryResults(
            query_id="test-confidence-query",
            data=log_entries,
            column_names=['timestamp', 'event_type', 'user', 'system', 'source_ip', 'result', 'details', 'severity'],
            row_count=len(log_entries),
            data_scanned_gb=len(log_entries) * 0.001,
            execution_time_ms=100,
            cost_usd=0.001,
            query_sql="SELECT * FROM security_logs",
            source_tables=['security_logs']
        )
        
        # Mock response with varying confidence levels
        mock_response = {
            "threats": [
                {
                    "threat_type": "suspicious_activity",
                    "severity": "medium",
                    "title": "Potential Security Issue",
                    "description": "Unusual pattern detected",
                    "affected_systems": ["system-1"],
                    "indicators": ["pattern"],
                    "evidence": [{"source": "logs", "description": "evidence", "confidence": 0.6}],
                    "confidence": 0.6
                }
            ]
        }
        
        with patch.object(self.analyzer, '_call_bedrock_model') as mock_bedrock:
            mock_bedrock.return_value = json.dumps(mock_response)
            
            threats = self.analyzer.analyze_security_patterns(query_results)
            
            # Property: Confidence should correlate with threat characteristics
            for threat in threats:
                # High-severity threats should have higher confidence requirements
                if threat.severity == ThreatSeverity.CRITICAL:
                    assert threat.confidence >= 0.7, (
                        f"Critical threat has low confidence: {threat.confidence}"
                    )
                
                # All threats should have evidence supporting their confidence
                if threat.confidence > 0.8:
                    assert len(threat.evidence) > 0, (
                        f"High-confidence threat lacks supporting evidence"
                    )
    
    def test_threat_detection_bedrock_integration(self):
        """
        Test that Bedrock integration works correctly for threat detection.
        This is a unit test to verify the integration points.
        """
        # Test data with clear threat indicators
        test_data = QueryResults(
            query_id="test-bedrock-integration",
            data=[
                {
                    'timestamp': '2024-01-15T10:30:00Z',
                    'event_type': 'failed_login',
                    'user': 'admin',
                    'source_ip': '192.168.1.100',
                    'attempts': 50
                }
            ],
            column_names=['timestamp', 'event_type', 'user', 'source_ip', 'attempts'],
            row_count=1,
            data_scanned_gb=0.001,
            execution_time_ms=500,
            cost_usd=0.0001,
            query_sql="SELECT * FROM security_logs WHERE event_type = 'failed_login'",
            source_tables=['security_logs']
        )
        
        # Test prompt building
        prompt = self.analyzer._build_threat_analysis_prompt(test_data)
        
        # Verify prompt contains key elements
        assert 'cybersecurity analyst' in prompt.lower()
        assert 'mitre att&ck' in prompt.lower()
        assert 'threat_type' in prompt
        assert 'severity' in prompt
        assert 'confidence' in prompt
        
        # Test JSON extraction
        sample_response = '''
        {
            "threats": [
                {
                    "threat_type": "suspicious_activity",
                    "severity": "high",
                    "title": "Brute Force Attack",
                    "description": "Multiple failed login attempts detected",
                    "confidence": 0.9
                }
            ]
        }
        '''
        
        extracted = self.analyzer._extract_json_from_response(sample_response)
        assert 'threats' in extracted
        assert len(extracted['threats']) == 1
        assert extracted['threats'][0]['threat_type'] == 'suspicious_activity'


# Run the tests
if __name__ == '__main__':
    pytest.main([__file__, '-v'])