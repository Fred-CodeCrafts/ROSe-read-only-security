"""
Instant Insights Generator - Main orchestrator for security insights.

This module coordinates report generation, visualization creation, and action plan
development to provide comprehensive security insights for different audiences.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, Recommendation
from aws_bedrock_athena_ai.insights.models import (
    ExecutiveReport, TechnicalReport, ComplianceReport, 
    Visualization, ActionPlan, AudienceType
)
from aws_bedrock_athena_ai.insights.report_generator import ReportGenerator
from aws_bedrock_athena_ai.insights.visualization_generator import VisualizationGenerator
from aws_bedrock_athena_ai.insights.action_plan_generator import ActionPlanGenerator

logger = logging.getLogger(__name__)


class InstantInsightsGenerator:
    """
    Main class for generating instant security insights.
    
    Coordinates multi-audience report generation, visualization creation,
    and action plan development from threat analysis results.
    """
    
    def __init__(self):
        self.report_generator = ReportGenerator()
        self.visualization_generator = VisualizationGenerator()
        self.action_plan_generator = ActionPlanGenerator()
        
        logger.info("InstantInsightsGenerator initialized")
    
    def generate_executive_summary(self, analysis: ThreatAnalysis) -> ExecutiveReport:
        """
        Generate executive summary with business context.
        
        Args:
            analysis: Complete threat analysis results
            
        Returns:
            ExecutiveReport: Business-focused security report
        """
        logger.info(f"Generating executive summary for analysis {analysis.analysis_id}")
        return self.report_generator.generate_executive_summary(analysis)
    
    def create_technical_details(self, analysis: ThreatAnalysis) -> TechnicalReport:
        """
        Create technical detailed report for IT teams.
        
        Args:
            analysis: Complete threat analysis results
            
        Returns:
            TechnicalReport: Technical security report with implementation details
        """
        logger.info(f"Creating technical details for analysis {analysis.analysis_id}")
        return self.report_generator.create_technical_details(analysis)
    
    def build_action_plan(
        self, 
        recommendations: List[Recommendation],
        analysis: Optional[ThreatAnalysis] = None
    ) -> ActionPlan:
        """
        Build prioritized action plan from recommendations.
        
        Args:
            recommendations: List of security recommendations
            analysis: Optional threat analysis for additional context
            
        Returns:
            ActionPlan: Prioritized action plan with timeline and milestones
        """
        logger.info(f"Building action plan from {len(recommendations)} recommendations")
        return self.action_plan_generator.generate_prioritized_action_plan(
            recommendations, analysis
        )
    
    def generate_visualizations(
        self, 
        analysis: ThreatAnalysis,
        audience: AudienceType = AudienceType.EXECUTIVE,
        include_action_plan: bool = False
    ) -> List[Visualization]:
        """
        Generate comprehensive visualizations for security posture.
        
        Args:
            analysis: Threat analysis results
            audience: Target audience for visualizations
            include_action_plan: Whether to include action plan visualization
            
        Returns:
            List[Visualization]: Collection of security visualizations
        """
        logger.info(f"Generating visualizations for {audience.value} audience")
        
        visualizations = []
        
        # Core visualizations
        visualizations.append(
            self.visualization_generator.create_risk_dashboard(analysis, audience)
        )
        
        visualizations.append(
            self.visualization_generator.create_security_posture_chart(analysis, audience)
        )
        
        # Technical audience gets additional visualizations
        if audience in [AudienceType.TECHNICAL, AudienceType.OPERATIONS]:
            visualizations.append(
                self.visualization_generator.generate_threat_timeline(
                    analysis.threats_identified, audience
                )
            )
            
            visualizations.append(
                self.visualization_generator.create_trend_analysis_chart(analysis)
            )
        
        # Compliance audience gets compliance-specific visualizations
        if audience == AudienceType.COMPLIANCE:
            visualizations.append(
                self.visualization_generator.generate_compliance_status_chart(analysis)
            )
        
        # Add action plan visualization if requested
        if include_action_plan and analysis.recommendations:
            action_plan = self.build_action_plan(analysis.recommendations, analysis)
            visualizations.append(
                self.visualization_generator.generate_action_plan_visualization(action_plan)
            )
        
        return visualizations
    
    def create_comprehensive_insights_package(
        self, 
        analysis: ThreatAnalysis,
        target_audiences: Optional[List[AudienceType]] = None
    ) -> Dict[str, Any]:
        """
        Create comprehensive insights package for multiple audiences.
        
        Args:
            analysis: Complete threat analysis results
            target_audiences: List of target audiences (defaults to all)
            
        Returns:
            Dict containing reports, visualizations, and action plans for each audience
        """
        if not target_audiences:
            target_audiences = [
                AudienceType.EXECUTIVE, 
                AudienceType.TECHNICAL, 
                AudienceType.COMPLIANCE
            ]
        
        logger.info(f"Creating comprehensive insights for audiences: {[a.value for a in target_audiences]}")
        
        insights_package = {
            "analysis_id": analysis.analysis_id,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_threats": len(analysis.threats_identified),
                "risk_score": analysis.risk_assessment.overall_risk_score,
                "critical_issues": analysis.risk_assessment.critical_threats,
                "recommendations_count": len(analysis.recommendations)
            },
            "audiences": {}
        }
        
        # Generate insights for each audience
        for audience in target_audiences:
            audience_insights = {
                "visualizations": self.generate_visualizations(analysis, audience),
                "action_plan": None
            }
            
            # Generate audience-specific reports
            if audience == AudienceType.EXECUTIVE:
                audience_insights["report"] = self.generate_executive_summary(analysis)
            elif audience == AudienceType.TECHNICAL:
                audience_insights["report"] = self.create_technical_details(analysis)
            elif audience == AudienceType.COMPLIANCE:
                audience_insights["report"] = self._create_compliance_report(analysis)
            
            # Generate action plan for operational audiences
            if audience in [AudienceType.TECHNICAL, AudienceType.OPERATIONS] and analysis.recommendations:
                audience_insights["action_plan"] = self.build_action_plan(
                    analysis.recommendations, analysis
                )
            
            insights_package["audiences"][audience.value] = audience_insights
        
        # Generate unified action plan
        if analysis.recommendations:
            insights_package["unified_action_plan"] = self.build_action_plan(
                analysis.recommendations, analysis
            )
        
        return insights_package
    
    def explain_security_concepts(
        self, 
        concept: str, 
        audience: AudienceType = AudienceType.EXECUTIVE
    ) -> str:
        """
        Explain security concepts in audience-appropriate language.
        
        Args:
            concept: Security concept to explain
            audience: Target audience for explanation
            
        Returns:
            str: Audience-appropriate explanation
        """
        logger.info(f"Explaining concept '{concept}' for {audience.value} audience")
        
        explanations = {
            AudienceType.EXECUTIVE: {
                "threat": "A potential security risk that could harm your business operations, data, or reputation",
                "vulnerability": "A weakness in your systems that attackers could exploit to gain unauthorized access",
                "risk_score": "A numerical rating (1-10) indicating your overall security risk level, where 10 is highest risk",
                "mitigation": "Actions taken to reduce or eliminate security risks",
                "compliance": "Meeting regulatory and industry security standards to avoid penalties and maintain trust"
            },
            AudienceType.TECHNICAL: {
                "threat": "A potential attack vector or malicious activity targeting system vulnerabilities",
                "vulnerability": "A security flaw in software, configuration, or processes that can be exploited",
                "risk_score": "Calculated metric based on threat likelihood, impact, and current control effectiveness",
                "mitigation": "Technical controls and procedures implemented to reduce attack surface and impact",
                "compliance": "Adherence to security frameworks and standards through technical and procedural controls"
            },
            AudienceType.COMPLIANCE: {
                "threat": "A risk factor that could lead to compliance violations or regulatory penalties",
                "vulnerability": "A gap in controls that could result in audit findings or compliance failures",
                "risk_score": "Quantified assessment of compliance risk exposure across regulatory requirements",
                "mitigation": "Control implementations that address specific compliance requirements",
                "compliance": "Systematic adherence to regulatory frameworks through documented controls and evidence"
            }
        }
        
        audience_explanations = explanations.get(audience, explanations[AudienceType.EXECUTIVE])
        return audience_explanations.get(concept.lower(), f"Security concept: {concept}")
    
    def generate_evidence_links(self, analysis: ThreatAnalysis) -> Dict[str, List[str]]:
        """
        Generate evidence links and citations for analysis results.
        
        Args:
            analysis: Threat analysis results
            
        Returns:
            Dict mapping findings to evidence sources
        """
        logger.info("Generating evidence links for analysis results")
        
        evidence_links = {}
        
        for threat in analysis.threats_identified:
            threat_evidence = []
            
            for evidence in threat.evidence:
                evidence_entry = f"{evidence.source} ({evidence.timestamp.strftime('%Y-%m-%d %H:%M')})"
                if evidence.confidence >= 0.8:
                    evidence_entry += " [High Confidence]"
                threat_evidence.append(evidence_entry)
            
            evidence_links[threat.threat_id] = threat_evidence
        
        return evidence_links
    
    def _create_compliance_report(self, analysis: ThreatAnalysis) -> ComplianceReport:
        """Create compliance-focused report"""
        # This would be implemented similar to other report types
        # For now, return a basic compliance report structure
        
        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            title=f"Compliance Assessment Report - {datetime.now().strftime('%B %Y')}",
            compliance_summary=f"Compliance assessment based on {len(analysis.threats_identified)} security findings",
            framework_assessments={
                "SOC2": {"score": 78, "status": "partial_compliance"},
                "ISO27001": {"score": 82, "status": "compliant"},
                "NIST": {"score": 75, "status": "partial_compliance"}
            },
            gaps_identified=[
                {
                    "framework": "SOC2",
                    "requirement": "CC6.1 - Logical Access Controls",
                    "gap": "Insufficient access review procedures",
                    "severity": "medium"
                }
            ],
            compliance_score=78.5,
            audit_findings=[
                {
                    "finding": "Access control gaps identified",
                    "severity": "medium",
                    "recommendation": "Implement quarterly access reviews"
                }
            ],
            remediation_timeline={
                "immediate": 2,
                "short_term": 5,
                "long_term": 3
            }
        )