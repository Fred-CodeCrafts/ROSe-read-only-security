"""
Expert Reasoning Engine - Main orchestrator for AI-powered security analysis.

This module coordinates threat analysis, risk assessment, and recommendation generation
to provide expert-level security insights using AWS Bedrock.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Optional

from aws_bedrock_athena_ai.reasoning_engine.threat_analyzer import ThreatAnalyzer
from aws_bedrock_athena_ai.reasoning_engine.risk_assessor import RiskAssessor
from aws_bedrock_athena_ai.reasoning_engine.recommendation_generator import RecommendationGenerator
from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, Threat, Pattern
from aws_bedrock_athena_ai.data_detective.models import QueryResults


logger = logging.getLogger(__name__)


class ExpertReasoningEngine:
    """
    Main orchestrator for expert-level security analysis using AWS Bedrock.
    
    This class coordinates the various AI-powered analysis components to provide
    comprehensive threat analysis, risk assessment, and actionable recommendations.
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        """
        Initialize the Expert Reasoning Engine.
        
        Args:
            region_name: AWS region for Bedrock services
        """
        self.threat_analyzer = ThreatAnalyzer(region_name)
        self.risk_assessor = RiskAssessor()
        self.recommendation_generator = RecommendationGenerator(region_name)
        self.region_name = region_name
        
        logger.info(f"Expert Reasoning Engine initialized for region {region_name}")
    
    def analyze_security_data(self, data: QueryResults, analysis_context: Optional[dict] = None) -> ThreatAnalysis:
        """
        Perform comprehensive security analysis on the provided data.
        
        Args:
            data: Query results from Smart Data Detective
            analysis_context: Optional context for the analysis (user role, priority, etc.)
            
        Returns:
            Complete threat analysis with threats, risks, and recommendations
        """
        start_time = datetime.now()
        analysis_id = str(uuid.uuid4())
        
        try:
            logger.info(f"Starting security analysis {analysis_id} for {len(data.rows)} data points")
            
            # Step 1: Identify threats and patterns
            logger.info("Step 1: Analyzing threat patterns...")
            threats = self.threat_analyzer.analyze_security_patterns(data)
            patterns = self.threat_analyzer.identify_suspicious_patterns(data)
            
            # Step 2: Assess risks and prioritize threats
            logger.info("Step 2: Assessing risks and prioritizing threats...")
            risk_assessment = self.risk_assessor.assess_risk_levels(threats)
            prioritized_threats = self.risk_assessor.prioritize_threats(threats)
            
            # Step 3: Generate recommendations
            logger.info("Step 3: Generating security recommendations...")
            recommendations = self.recommendation_generator.generate_recommendations(prioritized_threats)
            recommendations_with_analysis = self.recommendation_generator.generate_cost_benefit_analysis(recommendations)
            
            # Step 4: Generate summaries
            logger.info("Step 4: Generating analysis summaries...")
            summary = self._generate_technical_summary(prioritized_threats, risk_assessment, recommendations_with_analysis)
            executive_summary = self._generate_executive_summary(prioritized_threats, risk_assessment, recommendations_with_analysis)
            
            # Calculate analysis duration
            analysis_duration = (datetime.now() - start_time).total_seconds()
            
            # Create comprehensive analysis result
            analysis = ThreatAnalysis(
                analysis_id=analysis_id,
                timestamp=start_time,
                threats_identified=prioritized_threats,
                risk_assessment=risk_assessment,
                patterns=patterns,
                recommendations=recommendations_with_analysis,
                confidence_level=self._calculate_overall_confidence(prioritized_threats),
                data_sources_analyzed=data.source_tables,
                analysis_duration=analysis_duration,
                model_used=self.threat_analyzer.model_id,
                summary=summary,
                executive_summary=executive_summary
            )
            
            logger.info(f"Security analysis {analysis_id} completed in {analysis_duration:.2f}s")
            logger.info(f"Found {len(prioritized_threats)} threats, {len(patterns)} patterns, {len(recommendations_with_analysis)} recommendations")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in security analysis {analysis_id}: {str(e)}")
            
            # Return minimal analysis with error information
            return ThreatAnalysis(
                analysis_id=analysis_id,
                timestamp=start_time,
                threats_identified=[],
                risk_assessment=self.risk_assessor.assess_risk_levels([]),
                patterns=[],
                recommendations=[],
                confidence_level=0.0,
                data_sources_analyzed=data.source_tables,
                analysis_duration=(datetime.now() - start_time).total_seconds(),
                model_used=self.threat_analyzer.model_id,
                summary=f"Analysis failed: {str(e)}",
                executive_summary=f"Security analysis encountered an error: {str(e)}"
            )
    
    def explain_security_concepts(self, concept: str, audience: str = "business") -> str:
        """
        Explain security concepts in audience-appropriate language.
        
        Args:
            concept: Security concept to explain
            audience: Target audience (business, technical, executive)
            
        Returns:
            Clear explanation tailored to the audience
        """
        try:
            # Use the threat analyzer's Bedrock connection for explanations
            prompt = self._build_explanation_prompt(concept, audience)
            explanation = self.threat_analyzer._call_bedrock_model(prompt)
            
            logger.info(f"Generated explanation for '{concept}' (audience: {audience})")
            return explanation
            
        except Exception as e:
            logger.error(f"Error explaining concept '{concept}': {str(e)}")
            return f"Unable to explain '{concept}' at this time. Please try again later."
    
    def _generate_technical_summary(self, threats: List[Threat], risk_assessment, recommendations) -> str:
        """Generate technical summary of the analysis."""
        if not threats:
            return "No significant security threats identified in the analyzed data."
        
        summary_parts = [
            f"Security Analysis Summary:",
            f"- {len(threats)} threats identified",
            f"- Overall risk level: {risk_assessment.risk_level.value.upper()}",
            f"- Risk score: {risk_assessment.overall_risk_score}/10",
            f"- {len(recommendations)} recommendations generated"
        ]
        
        # Add threat breakdown
        if risk_assessment.critical_threats > 0:
            summary_parts.append(f"- {risk_assessment.critical_threats} CRITICAL threats requiring immediate attention")
        if risk_assessment.high_threats > 0:
            summary_parts.append(f"- {risk_assessment.high_threats} HIGH severity threats")
        
        # Add top threats
        if threats:
            summary_parts.append("\nTop Threats:")
            for i, threat in enumerate(threats[:3], 1):
                summary_parts.append(f"{i}. {threat.title} ({threat.severity.value.upper()})")
        
        return "\n".join(summary_parts)
    
    def _generate_executive_summary(self, threats: List[Threat], risk_assessment, recommendations) -> str:
        """Generate executive summary in business-friendly language."""
        if not threats:
            return "Your security posture appears healthy with no significant threats detected in the analyzed data."
        
        # Determine overall message based on risk level
        risk_messages = {
            "critical": "URGENT ACTION REQUIRED: Critical security threats detected that could impact business operations.",
            "high": "HIGH PRIORITY: Significant security risks identified that require prompt attention.",
            "medium": "MODERATE RISK: Security issues detected that should be addressed to maintain good security posture.",
            "low": "LOW RISK: Minor security concerns identified with recommended improvements."
        }
        
        main_message = risk_messages.get(risk_assessment.risk_level.value, "Security analysis completed.")
        
        summary_parts = [
            main_message,
            f"\nKey Findings:",
            f"• {len(threats)} security issues identified",
            f"• Overall risk score: {risk_assessment.overall_risk_score}/10"
        ]
        
        # Add business impact context
        if risk_assessment.critical_threats > 0:
            summary_parts.append(f"• {risk_assessment.critical_threats} critical issue(s) that could disrupt business operations")
        
        # Add top recommendation
        if recommendations:
            top_rec = recommendations[0]
            summary_parts.append(f"\nImmediate Action: {top_rec.title}")
            summary_parts.append(f"Business Impact: {top_rec.business_impact}")
        
        return "\n".join(summary_parts)
    
    def _calculate_overall_confidence(self, threats: List[Threat]) -> float:
        """Calculate overall confidence level for the analysis."""
        if not threats:
            return 1.0  # High confidence in "no threats" if no data suggests otherwise
        
        # Average confidence of all threats, weighted by severity
        total_weighted_confidence = 0.0
        total_weight = 0.0
        
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        for threat in threats:
            weight = severity_weights.get(threat.severity.value, 1)
            total_weighted_confidence += threat.confidence * weight
            total_weight += weight
        
        if total_weight > 0:
            return round(total_weighted_confidence / total_weight, 2)
        else:
            return 0.5  # Default moderate confidence
    
    def _build_explanation_prompt(self, concept: str, audience: str) -> str:
        """Build prompt for explaining security concepts."""
        audience_context = {
            "business": "business executives and non-technical stakeholders",
            "technical": "IT professionals and system administrators", 
            "executive": "C-level executives and decision makers"
        }
        
        target_audience = audience_context.get(audience, "general audience")
        
        prompt = f"""
You are a cybersecurity expert explaining security concepts to {target_audience}.

Please explain the following security concept: "{concept}"

Guidelines for your explanation:
- Use clear, jargon-free language appropriate for {target_audience}
- Focus on practical implications and business impact
- Provide concrete examples when helpful
- Keep the explanation concise but comprehensive
- Include actionable insights when relevant

Provide a clear, helpful explanation that helps the audience understand both what this concept means and why it matters to them.
"""
        return prompt