"""
Tests for Smart Data Detective components.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, SecurityIntentType, TimeRange
from aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective
from aws_bedrock_athena_ai.data_detective.query_generator import QueryGenerator
from aws_bedrock_athena_ai.data_detective.data_correlator import DataCorrelator
from aws_bedrock_athena_ai.data_detective.models import (
    DataSource, DataSourceType, SchemaInfo, ColumnInfo, QueryResults
)


class TestQueryGenerator:
    """Test cases for QueryGenerator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.query_generator = QueryGenerator()
        
        # Create sample data source
        self.sample_source = DataSource(
            source_id="test_source_001",
            source_type=DataSourceType.SECURITY_LOGS,
            s3_location="s3://test-bucket/security-logs/",
            schema_info=SchemaInfo(
                table_name="security_events",
                columns=[
                    ColumnInfo("timestamp", "timestamp"),
                    ColumnInfo("event_type", "string"),
                    ColumnInfo("severity", "string"),
                    ColumnInfo("source_ip", "string"),
                    ColumnInfo("user_id", "string"),
                    ColumnInfo("action", "string"),
                    ColumnInfo("result", "string")
                ]
            ),
            confidence_score=0.9,
            estimated_size_gb=1.5
        )
    
    def test_generate_threat_hunting_query(self):
        """Test threat hunting query generation."""
        # Create threat hunting intent
        intent = SecurityIntent(
            intent_type=SecurityIntentType.THREAT_HUNTING,
            entities=[],
            confidence=0.9,
            original_question="Show me potential threats from last week"
        )
        
        # Create context with time range
        context = QueryContext(
            timeframe=TimeRange(
                start=datetime.now() - timedelta(days=7),
                end=datetime.now()
            ),
            priority_level="high"
        )
        
        # Generate query
        query = self.query_generator.generate_optimized_query(
            intent, context, [self.sample_source]
        )
        
        # Verify query structure
        assert "SELECT" in query.upper()
        assert "FROM security_events" in query
        assert "timestamp >=" in query
        assert "ORDER BY timestamp DESC" in query
        assert "LIMIT" in query.upper()
    
    def test_generate_compliance_query(self):
        """Test compliance checking query generation."""
        # Create compliance intent
        intent = SecurityIntent(
            intent_type=SecurityIntentType.COMPLIANCE_CHECK,
            entities=[],
            confidence=0.8,
            original_question="Check compliance status"
        )
        
        context = QueryContext(priority_level="medium")
        
        # Create config source
        config_source = DataSource(
            source_id="config_001",
            source_type=DataSourceType.SYSTEM_CONFIGS,
            s3_location="s3://test-bucket/configs/",
            schema_info=SchemaInfo(
                table_name="system_configs",
                columns=[
                    ColumnInfo("system_id", "string"),
                    ColumnInfo("config_type", "string"),
                    ColumnInfo("compliance_status", "string"),
                    ColumnInfo("last_modified", "timestamp")
                ]
            ),
            confidence_score=0.8,
            estimated_size_gb=0.5
        )
        
        query = self.query_generator.generate_optimized_query(
            intent, context, [config_source]
        )
        
        # Verify compliance-specific elements
        assert "compliance_status" in query
        assert "!= 'COMPLIANT'" in query or "NON_COMPLIANT" in query
    
    def test_cost_estimation(self):
        """Test query cost estimation."""
        query = "SELECT * FROM security_events WHERE timestamp >= '2024-01-01'"
        
        cost_estimate = self.query_generator.estimate_query_cost(
            query, [self.sample_source]
        )
        
        # Verify cost estimate structure
        assert cost_estimate.estimated_data_scanned_gb > 0
        assert cost_estimate.estimated_cost_usd >= 0
        assert 0 <= cost_estimate.confidence <= 1
        assert isinstance(cost_estimate.factors, list)
    
    def test_source_selection(self):
        """Test relevant source selection."""
        # Create multiple sources
        sources = [
            self.sample_source,
            DataSource(
                source_id="access_logs_001",
                source_type=DataSourceType.ACCESS_LOGS,
                s3_location="s3://test-bucket/access-logs/",
                schema_info=SchemaInfo(table_name="access_logs", columns=[]),
                confidence_score=0.7,
                estimated_size_gb=2.0
            )
        ]
        
        # Test threat hunting intent (should prefer security logs)
        intent = SecurityIntent(
            intent_type=SecurityIntentType.THREAT_HUNTING,
            entities=[],
            confidence=0.9
        )
        
        context = QueryContext()
        
        relevant_sources = self.query_generator._select_relevant_sources(
            intent, context, sources
        )
        
        # Should prefer security logs for threat hunting
        assert len(relevant_sources) > 0
        assert relevant_sources[0].source_type == DataSourceType.SECURITY_LOGS


class TestDataCorrelator:
    """Test cases for DataCorrelator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('boto3.client'):
            self.correlator = DataCorrelator()
        
        # Create sample query results
        self.primary_results = QueryResults(
            query_id="test_001",
            data=[
                {
                    'timestamp': '2024-01-15T10:00:00Z',
                    'source_ip': '192.168.1.100',
                    'user_id': 'user123',
                    'event_type': 'LOGIN_ATTEMPT',
                    'result': 'SUCCESS'
                },
                {
                    'timestamp': '2024-01-15T10:05:00Z',
                    'source_ip': '192.168.1.100',
                    'user_id': 'user123',
                    'event_type': 'FILE_ACCESS',
                    'result': 'SUCCESS'
                }
            ],
            column_names=['timestamp', 'source_ip', 'user_id', 'event_type', 'result'],
            row_count=2,
            data_scanned_gb=0.1,
            execution_time_ms=500,
            cost_usd=0.0005,
            query_sql="SELECT * FROM security_events",
            source_tables=['security_events']
        )
    
    def test_extract_correlation_keys(self):
        """Test extraction of correlation keys from query results."""
        correlation_keys = self.correlator._extract_correlation_keys(self.primary_results)
        
        # Verify extracted keys
        assert '192.168.1.100' in correlation_keys['ip_addresses']
        assert 'user123' in correlation_keys['user_ids']
        assert len(correlation_keys['timestamps']) == 2
        assert 'LOGIN_ATTEMPT' in correlation_keys['event_types']
    
    def test_temporal_correlation(self):
        """Test temporal correlation detection."""
        # Create related data with similar timestamps
        related_data = {
            'firewall_logs': QueryResults(
                query_id="fw_001",
                data=[
                    {
                        'timestamp': '2024-01-15T10:01:00Z',
                        'source_ip': '192.168.1.100',
                        'action': 'ALLOW',
                        'port': '443'
                    }
                ],
                column_names=['timestamp', 'source_ip', 'action', 'port'],
                row_count=1,
                data_scanned_gb=0.05,
                execution_time_ms=200,
                cost_usd=0.00025,
                query_sql="SELECT * FROM firewall_logs",
                source_tables=['firewall_logs']
            )
        }
        
        context = QueryContext()
        
        patterns = self.correlator._temporal_correlation(
            self.primary_results, related_data, context
        )
        
        # Should find temporal correlation
        assert len(patterns) > 0
        assert patterns[0].pattern_type == "temporal"
        assert patterns[0].confidence > 0
    
    def test_ip_based_correlation(self):
        """Test IP-based correlation detection."""
        # Create related data with overlapping IPs
        related_data = {
            'network_logs': QueryResults(
                query_id="net_001",
                data=[
                    {
                        'source_ip': '192.168.1.100',
                        'destination_ip': '10.0.0.1',
                        'protocol': 'TCP',
                        'port': '443'
                    }
                ],
                column_names=['source_ip', 'destination_ip', 'protocol', 'port'],
                row_count=1,
                data_scanned_gb=0.05,
                execution_time_ms=200,
                cost_usd=0.00025,
                query_sql="SELECT * FROM network_logs",
                source_tables=['network_logs']
            )
        }
        
        context = QueryContext()
        
        patterns = self.correlator._ip_based_correlation(
            self.primary_results, related_data, context
        )
        
        # Should find IP correlation
        assert len(patterns) > 0
        assert patterns[0].pattern_type == "ip_based"
        assert '192.168.1.100' in str(patterns[0].evidence)


class TestSmartDataDetective:
    """Test cases for SmartDataDetective integration."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('boto3.client'):
            self.detective = SmartDataDetective()
    
    @patch('boto3.client')
    def test_comprehensive_analysis(self, mock_boto_client):
        """Test comprehensive analysis workflow."""
        # Mock data source discovery
        with patch.object(self.detective, 'discover_security_data_sources') as mock_discover:
            mock_discover.return_value = [
                DataSource(
                    source_id="test_001",
                    source_type=DataSourceType.SECURITY_LOGS,
                    s3_location="s3://test/logs/",
                    schema_info=SchemaInfo(
                        table_name="security_events",
                        columns=[ColumnInfo("timestamp", "timestamp")]
                    ),
                    confidence_score=0.9,
                    estimated_size_gb=1.0
                )
            ]
            
            # Create test intent and context
            intent = SecurityIntent(
                intent_type=SecurityIntentType.THREAT_HUNTING,
                entities=[],
                confidence=0.9
            )
            
            context = QueryContext(
                timeframe=TimeRange(
                    start=datetime.now() - timedelta(days=1),
                    end=datetime.now()
                )
            )
            
            # Execute comprehensive analysis
            results = self.detective.execute_comprehensive_analysis(
                intent, context, include_correlation=True, include_trends=True
            )
            
            # Verify results structure
            assert 'data_sources_found' in results
            assert 'query' in results
            assert 'cost_estimate' in results
            assert results['data_sources_found'] > 0
            assert results['query'] is not None
    
    def test_optimization_recommendations(self):
        """Test query optimization recommendations."""
        from aws_bedrock_athena_ai.data_detective.models import CostEstimate
        
        # Test expensive query
        expensive_query = "SELECT * FROM large_table"
        expensive_estimate = CostEstimate(
            estimated_data_scanned_gb=10.0,
            estimated_cost_usd=0.05,
            confidence=0.8,
            factors=[]
        )
        
        recommendations = self.detective.get_optimization_recommendations(
            expensive_query, expensive_estimate
        )
        
        # Should recommend optimizations
        assert len(recommendations) > 0
        assert any("SELECT *" in rec for rec in recommendations)
        assert any("cost" in rec.lower() for rec in recommendations)


if __name__ == "__main__":
    pytest.main([__file__])