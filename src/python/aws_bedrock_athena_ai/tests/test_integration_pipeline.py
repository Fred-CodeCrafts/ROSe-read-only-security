"""
Integration tests for the complete AI Security Analyst pipeline.

Tests the end-to-end NLI → Athena → Bedrock → Insights workflow
with error handling and graceful degradation.
"""

import pytest
import uuid
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from aws_bedrock_athena_ai.integration.ai_security_analyst_pipeline import AISecurityAnalystPipeline, PipelineResult
from aws_bedrock_athena_ai.integration.error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, NLPResponse, SecurityIntentType
from aws_bedrock_athena_ai.data_detective.models import QueryResults
from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, RiskAssessment, RiskLevel
from aws_bedrock_athena_ai.insights.models import AudienceType


class TestAISecurityAnalystPipeline:
    """Test the complete AI Security Analyst pipeline integration."""
    
    @pytest.fixture
    def pipeline(self):
        """Create a pipeline instance for testing."""
        with patch('boto3.client'):
            return AISecurityAnalystPipeline(aws_region="us-east-1")
    
    @pytest.fixture
    def sample_nlp_response(self):
        """Create a sample NLP response."""
        intent = SecurityIntent(
            intent_type=SecurityIntentType.THREAT_HUNTING,
            confidence=0.9,
            clarification_needed=False,
            original_question="Are we being attacked right now?"
        )
        
        context = QueryContext(
            timeframe_start=datetime.now(),
            timeframe_end=datetime.now(),
            systems=['web_servers'],
            priority_level='high'
        )
        
        return NLPResponse(
            intent=intent,
            context=context,
            needs_clarification=False,
            processing_time_ms=150.0
        )
    
    @pytest.fixture
    def sample_query_results(self):
        """Create sample query results."""
        return QueryResults(
            query_id="test_query_123",
            data=[
                {
                    'timestamp': '2024-01-13T10:00:00Z',
                    'event_type': 'LOGIN_ATTEMPT',
                    'severity': 'HIGH',
                    'source_ip': '192.168.1.100',
                    'user_id': 'admin',
                    'action': 'LOGIN',
                    'result': 'FAILED'
                }
            ],
            column_names=['timestamp', 'event_type', 'severity', 'source_ip', 'user_id', 'action', 'result'],
            row_count=1,
            data_scanned_gb=0.001,
            execution_time_ms=500,
            cost_usd=0.005,
            query_sql="SELECT * FROM security_events WHERE timestamp > '2024-01-13'",
            source_tables=['security_events']
        )
    
    @pytest.fixture
    def sample_threat_analysis(self):
        """Create sample threat analysis."""
        return ThreatAnalysis(
            analysis_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            threats_identified=[],
            risk_assessment=RiskAssessment(
                overall_risk_score=3.5,
                risk_level=RiskLevel.MEDIUM,
                critical_threats=0,
                high_threats=1,
                medium_threats=2,
                low_threats=0
            ),
            patterns=[],
            recommendations=[],
            confidence_level=0.8,
            data_sources_analyzed=['security_events'],
            analysis_duration=2.5,
            model_used='claude-3',
            summary="Test analysis summary",
            executive_summary="Test executive summary"
        )
    
    def test_successful_pipeline_execution(self, pipeline, sample_nlp_response, 
                                         sample_query_results, sample_threat_analysis):
        """Test successful end-to-end pipeline execution."""
        
        # Mock all pipeline components
        with patch.object(pipeline.nlp_interface, 'parse_security_question', return_value=sample_nlp_response), \
             patch.object(pipeline.data_detective, 'discover_security_data_sources', return_value=[]), \
             patch.object(pipeline.data_detective, 'execute_comprehensive_analysis', return_value={
                 'data_sources_found': 1,
                 'primary_results': {'row_count': 1, 'execution_time_ms': 500},
                 'cost_estimate': {'estimated_cost_usd': 0.005, 'estimated_data_gb': 0.001}
             }), \
             patch.object(pipeline.reasoning_engine, 'analyze_security_data', return_value=sample_threat_analysis), \
             patch.object(pipeline.insights_generator, 'create_comprehensive_insights_package', return_value={
                 'analysis_id': sample_threat_analysis.analysis_id,
                 'audiences': {'executive': {'report': {}, 'visualizations': []}}
             }), \
             patch.object(pipeline.usage_tracker, 'can_execute_query', return_value=True), \
             patch.object(pipeline.usage_tracker, 'track_query_execution'), \
             patch.object(pipeline.audit_logger, 'log_security_query'), \
             patch.object(pipeline.audit_logger, 'log_analysis_completion'):
            
            # Execute pipeline
            result = pipeline.process_security_question(
                question="Are we being attacked right now?",
                user_id="test_user",
                max_cost_usd=0.10
            )
            
            # Verify successful execution
            assert result.success is True
            assert result.error_message is None
            assert result.nlp_response is not None
            assert result.threat_analysis is not None
            assert result.insights_package is not None
            assert result.processing_time_ms > 0
            assert result.cost_usd >= 0
    
    def test_nlp_clarification_needed(self, pipeline):
        """Test pipeline handling when NLP needs clarification."""
        
        # Create NLP response that needs clarification
        clarification_response = NLPResponse(
            intent=SecurityIntent(
                intent_type=SecurityIntentType.UNKNOWN,
                confidence=0.2,
                clarification_needed=True,
                clarification_questions=["What time period are you interested in?"],
                original_question="Show me stuff"
            ),
            context=QueryContext(),
            needs_clarification=True,
            processing_time_ms=100.0
        )
        
        with patch.object(pipeline.nlp_interface, 'parse_security_question', return_value=clarification_response), \
             patch.object(pipeline.audit_logger, 'log_security_query'):
            
            result = pipeline.process_security_question(
                question="Show me stuff",
                user_id="test_user"
            )
            
            # Verify clarification response
            assert result.success is True
            assert result.nlp_response.needs_clarification is True
            assert result.query_results is None
            assert result.threat_analysis is None
    
    def test_cost_limit_exceeded(self, pipeline, sample_nlp_response):
        """Test pipeline handling when cost limits are exceeded."""
        
        with patch.object(pipeline.nlp_interface, 'parse_security_question', return_value=sample_nlp_response), \
             patch.object(pipeline.usage_tracker, 'can_execute_query', return_value=False), \
             patch.object(pipeline.audit_logger, 'log_security_query'), \
             patch.object(pipeline.audit_logger, 'log_analysis_error'):
            
            result = pipeline.process_security_question(
                question="Analyze all security data",
                user_id="test_user",
                max_cost_usd=0.01
            )
            
            # Verify cost limit handling
            assert result.success is False
            assert "cost limits" in result.error_message.lower()
            assert len(result.warnings) > 0
    
    def test_no_data_sources_found(self, pipeline, sample_nlp_response):
        """Test pipeline handling when no data sources are found."""
        
        with patch.object(pipeline.nlp_interface, 'parse_security_question', return_value=sample_nlp_response), \
             patch.object(pipeline.data_detective, 'discover_security_data_sources', return_value=[]), \
             patch.object(pipeline.usage_tracker, 'can_execute_query', return_value=True), \
             patch.object(pipeline.audit_logger, 'log_security_query'), \
             patch.object(pipeline.audit_logger, 'log_analysis_error'):
            
            result = pipeline.process_security_question(
                question="Are we being attacked?",
                user_id="test_user"
            )
            
            # Verify no data sources handling
            assert result.success is False
            assert "no security data sources" in result.error_message.lower()
    
    def test_ai_analysis_failure_graceful_degradation(self, pipeline, sample_nlp_response, sample_query_results):
        """Test graceful degradation when AI analysis fails."""
        
        with patch.object(pipeline.nlp_interface, 'parse_security_question', return_value=sample_nlp_response), \
             patch.object(pipeline.data_detective, 'discover_security_data_sources', return_value=[Mock()]), \
             patch.object(pipeline.data_detective, 'execute_comprehensive_analysis', return_value={
                 'data_sources_found': 1,
                 'primary_results': {'row_count': 1, 'execution_time_ms': 500},
                 'cost_estimate': {'estimated_cost_usd': 0.005, 'estimated_data_gb': 0.001}
             }), \
             patch.object(pipeline.reasoning_engine, 'analyze_security_data', side_effect=Exception("Bedrock unavailable")), \
             patch.object(pipeline.usage_tracker, 'can_execute_query', return_value=True), \
             patch.object(pipeline.audit_logger, 'log_security_query'), \
             patch.object(pipeline.audit_logger, 'log_analysis_completion'):
            
            result = pipeline.process_security_question(
                question="Are we being attacked?",
                user_id="test_user"
            )
            
            # Verify graceful degradation
            assert result.success is True  # Should still succeed with degraded analysis
            assert result.threat_analysis is not None
            assert result.threat_analysis.confidence_level == 0.0  # Indicates degraded analysis
            assert len(result.warnings) > 0
            assert "ai analysis partially failed" in result.warnings[0].lower()
    
    def test_clarification_response_handling(self, pipeline):
        """Test handling of clarification responses."""
        
        # Mock successful clarification handling
        clarified_response = NLPResponse(
            intent=SecurityIntent(
                intent_type=SecurityIntentType.THREAT_HUNTING,
                confidence=0.9,
                clarification_needed=False,
                original_question="Are we being attacked in the last 24 hours?"
            ),
            context=QueryContext(),
            needs_clarification=False,
            processing_time_ms=120.0
        )
        
        with patch.object(pipeline.nlp_interface, 'handle_clarification_response', return_value=clarified_response), \
             patch.object(pipeline, 'process_security_question', return_value=PipelineResult(
                 session_id=str(uuid.uuid4()),
                 success=True
             )):
            
            result = pipeline.handle_clarification_response(
                original_question="Are we being attacked?",
                clarification_response="In the last 24 hours",
                conversation_id="conv_123",
                user_id="test_user"
            )
            
            assert result.success is True
    
    def test_pipeline_status_check(self, pipeline):
        """Test pipeline status and health check."""
        
        with patch.object(pipeline.usage_tracker, 'get_current_usage', return_value={'queries_today': 5}):
            
            status = pipeline.get_pipeline_status()
            
            assert status['pipeline_healthy'] is True
            assert 'components' in status
            assert 'usage_stats' in status
            assert 'timestamp' in status
            
            # Check component status
            components = status['components']
            assert 'nlp_interface' in components
            assert 'data_detective' in components
            assert 'reasoning_engine' in components
            assert 'insights_generator' in components
    
    def test_example_questions_retrieval(self, pipeline):
        """Test retrieval of example questions."""
        
        with patch.object(pipeline.nlp_interface, 'get_example_questions', return_value=[
            "Are we being attacked right now?",
            "Show me security threats from last week"
        ]):
            
            examples = pipeline.get_example_questions()
            
            assert len(examples) >= 2
            assert isinstance(examples[0], str)


class TestErrorHandler:
    """Test the error handler functionality."""
    
    @pytest.fixture
    def error_handler(self):
        """Create an error handler instance."""
        return ErrorHandler()
    
    def test_nlp_error_handling(self, error_handler):
        """Test handling of NLP errors."""
        
        error = ValueError("Ambiguous security question")
        context = {"component": "nlp", "question": "show me stuff"}
        
        response = error_handler.handle_error(error, context)
        
        assert response.category == ErrorCategory.NLP_ERROR
        assert response.severity == ErrorSeverity.LOW
        assert "understanding" in response.user_message.lower()
        assert len(response.suggestions) > 0
        assert response.can_retry is False  # NLP errors need user input
    
    def test_data_access_error_handling(self, error_handler):
        """Test handling of data access errors."""
        
        error = Exception("Access denied to S3 bucket")
        context = {"component": "data_detective"}
        
        response = error_handler.handle_error(error, context)
        
        assert response.category == ErrorCategory.DATA_ACCESS_ERROR
        assert response.severity == ErrorSeverity.HIGH
        assert "access" in response.user_message.lower()
        assert response.can_retry is True
        assert response.fallback_available is True
    
    def test_ai_analysis_error_handling(self, error_handler):
        """Test handling of AI analysis errors."""
        
        error = Exception("Bedrock service temporarily unavailable")
        context = {"component": "reasoning_engine"}
        
        response = error_handler.handle_error(error, context)
        
        assert response.category == ErrorCategory.AI_ANALYSIS_ERROR
        assert response.severity == ErrorSeverity.HIGH
        assert "ai analysis" in response.user_message.lower()
        assert response.can_retry is True
        assert response.fallback_available is True
    
    def test_cost_limit_error_handling(self, error_handler):
        """Test handling of cost limit errors."""
        
        error = Exception("Query cost exceeds Free Tier limits")
        context = {"component": "cost_optimizer"}
        
        response = error_handler.handle_error(error, context)
        
        assert response.category == ErrorCategory.COST_LIMIT_ERROR
        assert response.severity == ErrorSeverity.MEDIUM
        assert "cost limits" in response.user_message.lower()
        assert response.can_retry is False  # Need optimization first
        assert len(response.suggestions) > 0
    
    def test_unknown_error_handling(self, error_handler):
        """Test handling of unknown errors."""
        
        error = RuntimeError("Unexpected system error")
        context = {"component": "unknown"}
        
        response = error_handler.handle_error(error, context)
        
        assert response.category == ErrorCategory.UNKNOWN_ERROR
        assert response.severity == ErrorSeverity.LOW
        assert "unexpected error" in response.user_message.lower()
        assert response.can_retry is True


if __name__ == "__main__":
    pytest.main([__file__])