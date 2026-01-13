"""
AI Security Analyst Pipeline - Main integration component.

This module wires together the complete NLI → Athena → Bedrock → Insights pipeline
with comprehensive error handling and graceful degradation.
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from aws_bedrock_athena_ai.nlp.natural_language_interface import NaturalLanguageInterface
from aws_bedrock_athena_ai.nlp.models import NLPResponse, SecurityIntent, QueryContext
from aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective
from aws_bedrock_athena_ai.data_detective.models import QueryResults
from aws_bedrock_athena_ai.reasoning_engine.expert_reasoning_engine import ExpertReasoningEngine
from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis
from aws_bedrock_athena_ai.insights.instant_insights_generator import InstantInsightsGenerator
from insights.models import AudienceType
from cost_optimization.usage_tracker import UsageTracker
from security.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Result of complete pipeline execution."""
    session_id: str
    success: bool
    nlp_response: Optional[NLPResponse] = None
    query_results: Optional[QueryResults] = None
    threat_analysis: Optional[ThreatAnalysis] = None
    insights_package: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    processing_time_ms: float = 0.0
    cost_usd: float = 0.0
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class AISecurityAnalystPipeline:
    """
    Main pipeline that orchestrates the complete AI Security Analyst workflow.
    
    This class integrates:
    - Natural Language Interface (NLI)
    - Smart Data Detective (Athena integration)
    - Expert Reasoning Engine (Bedrock integration)
    - Instant Insights Generator
    
    With comprehensive error handling and graceful degradation.
    """
    
    def __init__(self, aws_region: str = "us-east-1"):
        """
        Initialize the AI Security Analyst Pipeline.
        
        Args:
            aws_region: AWS region for services
        """
        self.aws_region = aws_region
        
        # Initialize components
        try:
            self.nlp_interface = NaturalLanguageInterface()
            self.data_detective = SmartDataDetective(aws_region)
            self.reasoning_engine = ExpertReasoningEngine(aws_region)
            self.insights_generator = InstantInsightsGenerator()
            self.usage_tracker = UsageTracker()
            self.audit_logger = AuditLogger()
            
            logger.info(f"AI Security Analyst Pipeline initialized for region {aws_region}")
            
        except Exception as e:
            logger.error(f"Failed to initialize pipeline: {str(e)}")
            raise
    
    def process_security_question(
        self,
        question: str,
        user_id: str,
        conversation_id: Optional[str] = None,
        target_audiences: Optional[List[AudienceType]] = None,
        include_visualizations: bool = True,
        max_cost_usd: float = 0.05
    ) -> PipelineResult:
        """
        Process a complete security question through the full pipeline.
        
        Args:
            question: Natural language security question
            user_id: ID of the user asking the question
            conversation_id: Optional conversation ID for multi-turn conversations
            target_audiences: Target audiences for insights generation
            include_visualizations: Whether to generate visualizations
            max_cost_usd: Maximum allowed cost for the query
            
        Returns:
            PipelineResult: Complete pipeline execution result
        """
        session_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Starting pipeline session {session_id} for user {user_id}")
        logger.info(f"Question: {question}")
        
        # Initialize result
        result = PipelineResult(
            session_id=session_id,
            success=False
        )
        
        try:
            # Audit log the request
            self.audit_logger.log_security_query(
                user_id=user_id,
                question=question,
                session_id=session_id,
                timestamp=start_time
            )
            
            # Step 1: Natural Language Processing
            logger.info("Step 1: Processing natural language question...")
            nlp_response = self._process_natural_language(
                question, conversation_id, result
            )
            
            if not nlp_response or nlp_response.needs_clarification:
                result.nlp_response = nlp_response
                result.success = True  # Clarification is a valid response
                return result
            
            result.nlp_response = nlp_response
            
            # Step 2: Data Discovery and Query Generation
            logger.info("Step 2: Discovering data and generating queries...")
            query_results = self._execute_data_discovery(
                nlp_response.intent, nlp_response.context, max_cost_usd, result
            )
            
            if not query_results:
                return result  # Error already logged in _execute_data_discovery
            
            result.query_results = query_results
            
            # Step 3: AI-Powered Threat Analysis
            logger.info("Step 3: Performing AI threat analysis...")
            threat_analysis = self._perform_threat_analysis(
                query_results, nlp_response.context, result
            )
            
            if not threat_analysis:
                return result  # Error already logged in _perform_threat_analysis
            
            result.threat_analysis = threat_analysis
            
            # Step 4: Generate Insights and Reports
            logger.info("Step 4: Generating insights and reports...")
            insights_package = self._generate_insights(
                threat_analysis, target_audiences, include_visualizations, result
            )
            
            if not insights_package:
                return result  # Error already logged in _generate_insights
            
            result.insights_package = insights_package
            
            # Calculate final metrics
            result.processing_time_ms = (datetime.now() - start_time).total_seconds() * 1000
            result.cost_usd = query_results.cost_usd if query_results else 0.0
            result.success = True
            
            # Track usage
            self.usage_tracker.track_query_execution(
                user_id=user_id,
                cost_usd=result.cost_usd,
                data_scanned_gb=query_results.data_scanned_gb if query_results else 0.0,
                processing_time_ms=result.processing_time_ms
            )
            
            # Audit log the successful completion
            self.audit_logger.log_analysis_completion(
                session_id=session_id,
                user_id=user_id,
                threats_found=len(threat_analysis.threats_identified),
                cost_usd=result.cost_usd,
                processing_time_ms=result.processing_time_ms
            )
            
            logger.info(f"Pipeline session {session_id} completed successfully")
            logger.info(f"Processing time: {result.processing_time_ms:.1f}ms, Cost: ${result.cost_usd:.4f}")
            
            return result
            
        except Exception as e:
            logger.error(f"Pipeline session {session_id} failed: {str(e)}")
            result.error_message = str(e)
            result.processing_time_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            # Audit log the failure
            self.audit_logger.log_analysis_error(
                session_id=session_id,
                user_id=user_id,
                error_message=str(e),
                processing_time_ms=result.processing_time_ms
            )
            
            return result
    
    def _process_natural_language(
        self, 
        question: str, 
        conversation_id: Optional[str],
        result: PipelineResult
    ) -> Optional[NLPResponse]:
        """Process natural language question with error handling."""
        try:
            nlp_response = self.nlp_interface.parse_security_question(
                question=question,
                conversation_id=conversation_id
            )
            
            if nlp_response.intent.confidence < 0.3:
                result.warnings.append("Low confidence in question understanding")
            
            return nlp_response
            
        except Exception as e:
            logger.error(f"NLP processing failed: {str(e)}")
            result.error_message = f"Failed to understand the question: {str(e)}"
            return None
    
    def _execute_data_discovery(
        self,
        intent: SecurityIntent,
        context: QueryContext,
        max_cost_usd: float,
        result: PipelineResult
    ) -> Optional[QueryResults]:
        """Execute data discovery and query generation with cost controls."""
        try:
            # Check usage limits first
            if not self.usage_tracker.can_execute_query(max_cost_usd):
                result.error_message = "Query would exceed cost limits or Free Tier usage"
                result.warnings.append("Consider optimizing your query or waiting for usage reset")
                return None
            
            # Discover data sources
            data_sources = self.data_detective.discover_security_data_sources()
            
            if not data_sources:
                result.error_message = "No security data sources found"
                result.warnings.append("Ensure your S3 buckets contain security data and are properly configured")
                return None
            
            # Generate optimized query
            query = self.data_detective.generate_optimized_query(
                intent, context, data_sources
            )
            
            # Estimate cost
            cost_estimate = self.data_detective.estimate_query_cost(query, data_sources)
            
            if cost_estimate.estimated_cost_usd > max_cost_usd:
                result.error_message = f"Query cost (${cost_estimate.estimated_cost_usd:.4f}) exceeds limit (${max_cost_usd:.4f})"
                result.warnings.extend(
                    self.data_detective.get_optimization_recommendations(query, cost_estimate)
                )
                return None
            
            # Execute comprehensive analysis (includes simulated query execution)
            analysis_results = self.data_detective.execute_comprehensive_analysis(
                intent, context, include_correlation=True, include_trends=True
            )
            
            if 'error' in analysis_results:
                result.error_message = analysis_results['error']
                return None
            
            # Convert to QueryResults format
            query_results = QueryResults(
                query_id=f"pipeline_{result.session_id}",
                data=analysis_results.get('primary_results', {}).get('sample_data', []),
                column_names=['timestamp', 'event_type', 'severity', 'source_ip', 'user_id', 'action', 'result'],
                row_count=analysis_results.get('primary_results', {}).get('row_count', 0),
                data_scanned_gb=analysis_results.get('cost_estimate', {}).get('estimated_data_gb', 0.0),
                execution_time_ms=analysis_results.get('primary_results', {}).get('execution_time_ms', 0),
                cost_usd=analysis_results.get('cost_estimate', {}).get('estimated_cost_usd', 0.0),
                query_sql=query,
                source_tables=[ds['source_id'] for ds in analysis_results.get('data_sources', [])]
            )
            
            # Add correlation and trend data as metadata
            query_results.metadata = {
                'correlation_data': analysis_results.get('correlation_data'),
                'trends': analysis_results.get('trends', []),
                'data_sources_found': analysis_results.get('data_sources_found', 0)
            }
            
            return query_results
            
        except Exception as e:
            logger.error(f"Data discovery failed: {str(e)}")
            result.error_message = f"Failed to analyze security data: {str(e)}"
            return None
    
    def _perform_threat_analysis(
        self,
        query_results: QueryResults,
        context: QueryContext,
        result: PipelineResult
    ) -> Optional[ThreatAnalysis]:
        """Perform AI-powered threat analysis with graceful degradation."""
        try:
            # Check if we have data to analyze
            if query_results.row_count == 0:
                logger.info("No data found for threat analysis")
                # Return empty analysis rather than failing
                return ThreatAnalysis(
                    analysis_id=str(uuid.uuid4()),
                    timestamp=datetime.now(),
                    threats_identified=[],
                    risk_assessment=self.reasoning_engine.risk_assessor.assess_risk_levels([]),
                    patterns=[],
                    recommendations=[],
                    confidence_level=1.0,  # High confidence in "no threats" when no data
                    data_sources_analyzed=query_results.source_tables,
                    analysis_duration=0.0,
                    model_used="bedrock-claude",
                    summary="No security data available for analysis",
                    executive_summary="No security events found in the analyzed timeframe"
                )
            
            # Perform comprehensive threat analysis
            threat_analysis = self.reasoning_engine.analyze_security_data(
                query_results,
                analysis_context={
                    'user_context': context.user_role if hasattr(context, 'user_role') else 'analyst',
                    'priority_level': context.priority_level if hasattr(context, 'priority_level') else 'normal',
                    'correlation_data': query_results.metadata.get('correlation_data') if hasattr(query_results, 'metadata') else None
                }
            )
            
            return threat_analysis
            
        except Exception as e:
            logger.error(f"Threat analysis failed: {str(e)}")
            
            # Graceful degradation - return basic analysis with error info
            result.warnings.append(f"AI analysis partially failed: {str(e)}")
            
            return ThreatAnalysis(
                analysis_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                threats_identified=[],
                risk_assessment=self.reasoning_engine.risk_assessor.assess_risk_levels([]),
                patterns=[],
                recommendations=[],
                confidence_level=0.0,
                data_sources_analyzed=query_results.source_tables,
                analysis_duration=0.0,
                model_used="bedrock-claude",
                summary=f"Analysis failed: {str(e)}",
                executive_summary=f"Unable to complete AI analysis due to technical issues: {str(e)}"
            )
    
    def _generate_insights(
        self,
        threat_analysis: ThreatAnalysis,
        target_audiences: Optional[List[AudienceType]],
        include_visualizations: bool,
        result: PipelineResult
    ) -> Optional[Dict[str, Any]]:
        """Generate insights and reports with error handling."""
        try:
            # Use default audiences if none specified
            if not target_audiences:
                target_audiences = [AudienceType.EXECUTIVE, AudienceType.TECHNICAL]
            
            # Generate comprehensive insights package
            insights_package = self.insights_generator.create_comprehensive_insights_package(
                threat_analysis, target_audiences
            )
            
            # Add visualizations if requested
            if include_visualizations:
                for audience in target_audiences:
                    try:
                        visualizations = self.insights_generator.generate_visualizations(
                            threat_analysis, audience, include_action_plan=True
                        )
                        insights_package["audiences"][audience.value]["visualizations"] = [
                            {
                                "title": viz.title,
                                "type": viz.visualization_type.value,
                                "description": viz.description,
                                "data": viz.data
                            } for viz in visualizations
                        ]
                    except Exception as viz_error:
                        logger.warning(f"Failed to generate visualizations for {audience.value}: {viz_error}")
                        result.warnings.append(f"Visualization generation failed for {audience.value} audience")
            
            return insights_package
            
        except Exception as e:
            logger.error(f"Insights generation failed: {str(e)}")
            result.error_message = f"Failed to generate insights: {str(e)}"
            return None
    
    def handle_clarification_response(
        self,
        original_question: str,
        clarification_response: str,
        conversation_id: str,
        user_id: str
    ) -> PipelineResult:
        """
        Handle user response to clarification questions.
        
        Args:
            original_question: The original ambiguous question
            clarification_response: User's clarification response
            conversation_id: Conversation ID
            user_id: User ID
            
        Returns:
            PipelineResult: Result of processing clarified question
        """
        try:
            # Handle clarification through NLP interface
            clarified_response = self.nlp_interface.handle_clarification_response(
                original_question, clarification_response, conversation_id
            )
            
            if clarified_response and not clarified_response.needs_clarification:
                # Process the clarified question through full pipeline
                return self.process_security_question(
                    clarified_response.intent.original_question,
                    user_id,
                    conversation_id
                )
            else:
                # Still needs more clarification
                return PipelineResult(
                    session_id=str(uuid.uuid4()),
                    success=True,
                    nlp_response=clarified_response,
                    error_message="Additional clarification needed"
                )
                
        except Exception as e:
            logger.error(f"Clarification handling failed: {str(e)}")
            return PipelineResult(
                session_id=str(uuid.uuid4()),
                success=False,
                error_message=f"Failed to process clarification: {str(e)}"
            )
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """
        Get current pipeline status and health information.
        
        Returns:
            Dict containing pipeline component status
        """
        try:
            status = {
                "pipeline_healthy": True,
                "components": {
                    "nlp_interface": {"status": "healthy", "supported_intents": len(self.nlp_interface.get_supported_intents())},
                    "data_detective": {"status": "healthy", "region": self.data_detective.aws_region},
                    "reasoning_engine": {"status": "healthy", "region": self.reasoning_engine.region_name},
                    "insights_generator": {"status": "healthy"}
                },
                "usage_stats": self.usage_tracker.get_current_usage(),
                "timestamp": datetime.now().isoformat()
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get pipeline status: {str(e)}")
            return {
                "pipeline_healthy": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def get_example_questions(self) -> List[str]:
        """Get example questions that demonstrate pipeline capabilities."""
        return self.nlp_interface.get_example_questions()
    
    def clear_conversation_context(self, conversation_id: str) -> None:
        """Clear conversation context for a given conversation ID."""
        self.nlp_interface.clear_conversation_context(conversation_id)