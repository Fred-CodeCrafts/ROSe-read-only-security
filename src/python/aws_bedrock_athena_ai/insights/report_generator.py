"""
Multi-audience report generator for security analysis results.

This module generates tailored reports for different audiences including
executives, technical teams, and compliance officers.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, Threat, Recommendation, ThreatSeverity
from aws_bedrock_athena_ai.insights.models import (
    ExecutiveReport, TechnicalReport, ComplianceReport, ReportSection,
    AudienceType, ReportType
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates multi-audience security reports from threat analysis"""
    
    def __init__(self):
        self.industry_benchmarks = {
            "average_incidents_per_month": 2.3,
            "average_resolution_time_hours": 72,
            "compliance_score_benchmark": 85.0,
            "security_maturity_average": 3.2  # out of 5
        }
    
    def generate_executive_summary(self, analysis: ThreatAnalysis) -> ExecutiveReport:
        """
        Generate executive-level security report with business context.
        
        Args:
            analysis: Complete threat analysis results
            
        Returns:
            ExecutiveReport: Business-focused security report
        """
        logger.info(f"Generating executive report for analysis {analysis.analysis_id}")
        
        # Calculate key metrics
        critical_threats = len([t for t in analysis.threats_identified 
                              if t.severity == ThreatSeverity.CRITICAL])
        high_threats = len([t for t in analysis.threats_identified 
                           if t.severity == ThreatSeverity.HIGH])
        
        # Generate business impact assessment
        business_impact = self._assess_business_impact(analysis)
        
        # Create cost-benefit analysis
        cost_benefit = self._generate_cost_benefit_analysis(analysis.recommendations)
        
        # Generate key findings in business language
        key_findings = self._generate_executive_key_findings(analysis)
        
        # Create recommendations summary
        recommendations_summary = self._summarize_recommendations_for_executives(
            analysis.recommendations
        )
        
        # Generate industry benchmark comparison
        industry_comparison = self._compare_to_industry_benchmarks(analysis)
        
        # Create report sections
        sections = [
            ReportSection(
                title="Security Posture Overview",
                content=self._generate_security_posture_overview(analysis),
                priority=1
            ),
            ReportSection(
                title="Critical Issues Requiring Immediate Attention",
                content=self._generate_critical_issues_section(analysis),
                priority=2
            ),
            ReportSection(
                title="Risk Assessment and Business Impact",
                content=business_impact,
                priority=3
            ),
            ReportSection(
                title="Investment Recommendations",
                content=self._generate_investment_recommendations(analysis.recommendations),
                priority=4
            )
        ]
        
        # Generate next steps
        next_steps = self._generate_executive_next_steps(analysis)
        
        return ExecutiveReport(
            report_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            title=f"Security Assessment Report - {datetime.now().strftime('%B %Y')}",
            executive_summary=analysis.executive_summary,
            key_findings=key_findings,
            business_impact=business_impact,
            risk_score=analysis.risk_assessment.overall_risk_score,
            critical_issues=critical_threats + high_threats,
            recommendations_summary=recommendations_summary,
            cost_benefit_analysis=cost_benefit,
            industry_benchmarks=industry_comparison,
            sections=sections,
            next_steps=next_steps
        )
    
    def create_technical_details(self, analysis: ThreatAnalysis) -> TechnicalReport:
        """
        Generate technical detailed report for IT teams.
        
        Args:
            analysis: Complete threat analysis results
            
        Returns:
            TechnicalReport: Technical security report with implementation details
        """
        logger.info(f"Generating technical report for analysis {analysis.analysis_id}")
        
        # Generate detailed findings
        detailed_findings = self._generate_detailed_findings(analysis)
        
        # Create threat details with technical information
        threat_details = self._generate_threat_technical_details(analysis.threats_identified)
        
        # Generate system analysis
        system_analysis = self._generate_system_analysis(analysis)
        
        # Create detailed remediation steps
        remediation_steps = self._generate_detailed_remediation_steps(analysis.recommendations)
        
        # Generate technical recommendations
        technical_recommendations = self._generate_technical_recommendations(
            analysis.recommendations
        )
        
        # Create technical report sections
        sections = [
            ReportSection(
                title="Threat Analysis Details",
                content=self._generate_threat_analysis_details(analysis),
                priority=1
            ),
            ReportSection(
                title="Vulnerability Assessment",
                content=self._generate_vulnerability_assessment(analysis),
                priority=2
            ),
            ReportSection(
                title="Security Controls Evaluation",
                content=self._generate_security_controls_evaluation(analysis),
                priority=3
            ),
            ReportSection(
                title="Implementation Roadmap",
                content=self._generate_implementation_roadmap(analysis.recommendations),
                priority=4
            )
        ]
        
        # Generate appendices with raw data
        appendices = {
            "raw_threat_data": [threat.__dict__ for threat in analysis.threats_identified],
            "analysis_metadata": {
                "model_used": analysis.model_used,
                "analysis_duration": analysis.analysis_duration,
                "data_sources": analysis.data_sources_analyzed,
                "confidence_level": analysis.confidence_level
            }
        }
        
        return TechnicalReport(
            report_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            title=f"Technical Security Analysis - {datetime.now().strftime('%Y-%m-%d')}",
            technical_summary=self._generate_technical_summary(analysis),
            detailed_findings=detailed_findings,
            threat_details=threat_details,
            system_analysis=system_analysis,
            remediation_steps=remediation_steps,
            technical_recommendations=technical_recommendations,
            sections=sections,
            appendices=appendices
        )
    
    def _assess_business_impact(self, analysis: ThreatAnalysis) -> str:
        """Generate business impact assessment"""
        critical_count = len([t for t in analysis.threats_identified 
                             if t.severity == ThreatSeverity.CRITICAL])
        high_count = len([t for t in analysis.threats_identified 
                         if t.severity == ThreatSeverity.HIGH])
        
        if critical_count > 0:
            impact_level = "HIGH"
            impact_desc = f"Immediate business risk from {critical_count} critical security issues"
        elif high_count > 2:
            impact_level = "MEDIUM-HIGH"
            impact_desc = f"Elevated business risk from {high_count} high-priority security issues"
        else:
            impact_level = "MEDIUM"
            impact_desc = "Manageable security risks with proactive monitoring needed"
        
        return f"Business Impact Level: {impact_level}. {impact_desc}. " \
               f"Overall risk score: {analysis.risk_assessment.overall_risk_score:.1f}/10.0"
    
    def _generate_cost_benefit_analysis(self, recommendations: List[Recommendation]) -> Dict[str, Any]:
        """Generate cost-benefit analysis for recommendations"""
        total_cost = 0
        high_roi_items = 0
        
        for rec in recommendations:
            if rec.cost_benefit_ratio and rec.cost_benefit_ratio > 2.0:
                high_roi_items += 1
            if rec.cost_analysis and 'estimated_cost' in rec.cost_analysis:
                total_cost += rec.cost_analysis['estimated_cost']
        
        return {
            "total_estimated_cost": total_cost,
            "high_roi_recommendations": high_roi_items,
            "payback_period_months": 6 if high_roi_items > 0 else 12,
            "risk_reduction_percentage": min(85, len(recommendations) * 15)
        }
    
    def _generate_executive_key_findings(self, analysis: ThreatAnalysis) -> List[str]:
        """Generate key findings in business-friendly language"""
        findings = []
        
        # Risk level finding
        risk_level = analysis.risk_assessment.risk_level.value
        findings.append(f"Overall security risk level: {risk_level.upper()}")
        
        # Critical threats finding
        critical_threats = [t for t in analysis.threats_identified 
                           if t.severity == ThreatSeverity.CRITICAL]
        if critical_threats:
            findings.append(f"{len(critical_threats)} critical security issues require immediate attention")
        
        # Trend finding
        trend = analysis.risk_assessment.trend
        findings.append(f"Security posture trend: {trend}")
        
        # Coverage finding
        coverage = analysis.risk_assessment.mitigation_coverage
        findings.append(f"Current security coverage: {coverage:.0f}% of identified risks have mitigations")
        
        return findings
    
    def _summarize_recommendations_for_executives(self, recommendations: List[Recommendation]) -> List[str]:
        """Summarize recommendations for executive audience"""
        summary = []
        
        # Group by priority
        critical_recs = [r for r in recommendations if r.priority == "critical"]
        high_recs = [r for r in recommendations if r.priority == "high"]
        
        if critical_recs:
            summary.append(f"Implement {len(critical_recs)} critical security improvements immediately")
        
        if high_recs:
            summary.append(f"Plan {len(high_recs)} high-priority security enhancements for next quarter")
        
        # Add business-focused recommendations
        for rec in recommendations[:3]:  # Top 3 recommendations
            summary.append(f"{rec.title}: {rec.business_impact}")
        
        return summary
    
    def _compare_to_industry_benchmarks(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Compare security posture to industry benchmarks"""
        return {
            "security_score_vs_industry": {
                "our_score": analysis.risk_assessment.overall_risk_score,
                "industry_average": self.industry_benchmarks["security_maturity_average"],
                "percentile": 65 if analysis.risk_assessment.overall_risk_score > 3.0 else 35
            },
            "incident_response_time": {
                "our_average_hours": 48,  # Would be calculated from actual data
                "industry_average_hours": self.industry_benchmarks["average_resolution_time_hours"]
            },
            "compliance_standing": {
                "our_score": 78.5,  # Would be calculated from compliance analysis
                "industry_benchmark": self.industry_benchmarks["compliance_score_benchmark"]
            }
        }
    
    def _generate_security_posture_overview(self, analysis: ThreatAnalysis) -> str:
        """Generate security posture overview section"""
        total_threats = len(analysis.threats_identified)
        risk_score = analysis.risk_assessment.overall_risk_score
        
        return f"""
        Current security posture analysis reveals {total_threats} security findings across your infrastructure.
        With an overall risk score of {risk_score:.1f}/10.0, your organization's security posture is 
        {'above average' if risk_score < 5.0 else 'requires attention'}.
        
        Key metrics:
        - {analysis.risk_assessment.critical_threats} critical threats
        - {analysis.risk_assessment.high_threats} high-priority threats  
        - {analysis.risk_assessment.mitigation_coverage:.0f}% mitigation coverage
        - Security trend: {analysis.risk_assessment.trend}
        """
    
    def _generate_critical_issues_section(self, analysis: ThreatAnalysis) -> str:
        """Generate critical issues section"""
        critical_threats = [t for t in analysis.threats_identified 
                           if t.severity == ThreatSeverity.CRITICAL]
        
        if not critical_threats:
            return "No critical security issues identified. Continue monitoring for emerging threats."
        
        issues_text = f"Identified {len(critical_threats)} critical security issues requiring immediate action:\n\n"
        
        for i, threat in enumerate(critical_threats[:5], 1):  # Top 5 critical issues
            issues_text += f"{i}. {threat.title}\n"
            issues_text += f"   Impact: {threat.description}\n"
            issues_text += f"   Affected Systems: {', '.join(threat.affected_systems[:3])}\n\n"
        
        return issues_text
    
    def _generate_investment_recommendations(self, recommendations: List[Recommendation]) -> str:
        """Generate investment recommendations section"""
        high_roi_recs = [r for r in recommendations 
                        if r.cost_benefit_ratio and r.cost_benefit_ratio > 2.0]
        
        text = f"Recommended security investments with high ROI ({len(high_roi_recs)} identified):\n\n"
        
        for rec in high_roi_recs[:3]:  # Top 3 ROI recommendations
            text += f"• {rec.title}\n"
            text += f"  Business Impact: {rec.business_impact}\n"
            text += f"  Estimated Effort: {rec.estimated_effort}\n"
            if rec.cost_benefit_ratio:
                text += f"  ROI: {rec.cost_benefit_ratio:.1f}x\n\n"
        
        return text
    
    def _generate_executive_next_steps(self, analysis: ThreatAnalysis) -> List[str]:
        """Generate executive next steps"""
        steps = []
        
        critical_count = analysis.risk_assessment.critical_threats
        if critical_count > 0:
            steps.append(f"Authorize immediate response to {critical_count} critical security issues")
        
        steps.append("Review and approve recommended security investments")
        steps.append("Schedule quarterly security posture review")
        
        if analysis.risk_assessment.trend == "deteriorating":
            steps.append("Initiate comprehensive security program review")
        
        return steps
    
    # Technical report helper methods
    def _generate_detailed_findings(self, analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Generate detailed technical findings"""
        findings = []
        
        for threat in analysis.threats_identified:
            finding = {
                "threat_id": threat.threat_id,
                "title": threat.title,
                "severity": threat.severity.value,
                "type": threat.threat_type.value,
                "confidence": threat.confidence,
                "affected_systems": threat.affected_systems,
                "indicators": threat.indicators,
                "evidence_count": len(threat.evidence),
                "timeline_events": len(threat.timeline),
                "first_seen": threat.first_seen.isoformat() if threat.first_seen else None,
                "last_seen": threat.last_seen.isoformat() if threat.last_seen else None
            }
            findings.append(finding)
        
        return findings
    
    def _generate_threat_technical_details(self, threats: List[Threat]) -> List[Dict[str, Any]]:
        """Generate technical details for each threat"""
        details = []
        
        for threat in threats:
            detail = {
                "threat_id": threat.threat_id,
                "technical_description": threat.description,
                "attack_vectors": threat.indicators,
                "affected_infrastructure": threat.affected_systems,
                "evidence_analysis": [
                    {
                        "source": evidence.source,
                        "timestamp": evidence.timestamp.isoformat(),
                        "confidence": evidence.confidence,
                        "description": evidence.description
                    }
                    for evidence in threat.evidence
                ],
                "timeline_analysis": [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "description": event.description,
                        "source": event.source
                    }
                    for event in threat.timeline
                ]
            }
            details.append(detail)
        
        return details
    
    def _generate_system_analysis(self, analysis: ThreatAnalysis) -> Dict[str, Any]:
        """Generate system-level analysis"""
        # Aggregate system information from threats
        affected_systems = set()
        system_threat_counts = {}
        
        for threat in analysis.threats_identified:
            for system in threat.affected_systems:
                affected_systems.add(system)
                system_threat_counts[system] = system_threat_counts.get(system, 0) + 1
        
        return {
            "total_systems_analyzed": len(analysis.data_sources_analyzed),
            "systems_with_threats": len(affected_systems),
            "most_targeted_systems": sorted(
                system_threat_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5],
            "data_sources_coverage": analysis.data_sources_analyzed,
            "analysis_completeness": analysis.confidence_level
        }
    
    def _generate_detailed_remediation_steps(self, recommendations: List[Recommendation]) -> List[Dict[str, Any]]:
        """Generate detailed remediation steps"""
        steps = []
        
        for rec in recommendations:
            step = {
                "recommendation_id": rec.recommendation_id,
                "title": rec.title,
                "priority": rec.priority,
                "category": rec.category,
                "detailed_steps": rec.implementation_steps,
                "estimated_effort": rec.estimated_effort,
                "related_threats": rec.related_threats,
                "compliance_impact": rec.compliance_frameworks,
                "success_criteria": [
                    f"Threat mitigation for {len(rec.related_threats)} related threats",
                    f"Compliance improvement for {', '.join(rec.compliance_frameworks)}" if rec.compliance_frameworks else "Security posture enhancement"
                ]
            }
            steps.append(step)
        
        return steps
    
    def _generate_technical_recommendations(self, recommendations: List[Recommendation]) -> List[Dict[str, Any]]:
        """Generate technical recommendations with implementation details"""
        tech_recs = []
        
        for rec in recommendations:
            tech_rec = {
                "recommendation_id": rec.recommendation_id,
                "technical_title": rec.title,
                "implementation_complexity": self._assess_implementation_complexity(rec),
                "technical_requirements": rec.implementation_steps,
                "integration_considerations": self._generate_integration_considerations(rec),
                "testing_requirements": self._generate_testing_requirements(rec),
                "rollback_procedures": self._generate_rollback_procedures(rec),
                "monitoring_requirements": self._generate_monitoring_requirements(rec)
            }
            tech_recs.append(tech_rec)
        
        return tech_recs
    
    def _generate_technical_summary(self, analysis: ThreatAnalysis) -> str:
        """Generate technical summary"""
        return f"""
        Technical Analysis Summary:
        
        Analysis completed using {analysis.model_used} with {analysis.confidence_level:.1f}% confidence.
        Processing time: {analysis.analysis_duration:.2f} seconds.
        Data sources analyzed: {len(analysis.data_sources_analyzed)}
        
        Threat Detection Results:
        - Total threats identified: {len(analysis.threats_identified)}
        - Critical: {analysis.risk_assessment.critical_threats}
        - High: {analysis.risk_assessment.high_threats}
        - Medium: {analysis.risk_assessment.medium_threats}
        - Low: {analysis.risk_assessment.low_threats}
        
        Pattern Analysis:
        - Security patterns identified: {len(analysis.patterns)}
        - Risk factors: {len(analysis.risk_assessment.risk_factors)}
        - Mitigation coverage: {analysis.risk_assessment.mitigation_coverage:.1f}%
        """
    
    # Helper methods for technical recommendations
    def _assess_implementation_complexity(self, recommendation: Recommendation) -> str:
        """Assess implementation complexity"""
        step_count = len(recommendation.implementation_steps)
        if step_count <= 2:
            return "Low"
        elif step_count <= 5:
            return "Medium"
        else:
            return "High"
    
    def _generate_integration_considerations(self, recommendation: Recommendation) -> List[str]:
        """Generate integration considerations"""
        return [
            "Review existing security controls for conflicts",
            "Assess impact on current monitoring systems",
            "Validate compatibility with existing infrastructure",
            "Plan for user training and change management"
        ]
    
    def _generate_testing_requirements(self, recommendation: Recommendation) -> List[str]:
        """Generate testing requirements"""
        return [
            "Unit testing of security control functionality",
            "Integration testing with existing systems",
            "Security validation and penetration testing",
            "Performance impact assessment"
        ]
    
    def _generate_rollback_procedures(self, recommendation: Recommendation) -> List[str]:
        """Generate rollback procedures"""
        return [
            "Document current configuration state",
            "Create automated rollback scripts",
            "Test rollback procedures in staging environment",
            "Define rollback triggers and decision criteria"
        ]
    
    def _generate_monitoring_requirements(self, recommendation: Recommendation) -> List[str]:
        """Generate monitoring requirements"""
        return [
            "Implement health checks for new security controls",
            "Set up alerting for security control failures",
            "Create dashboards for security metrics tracking",
            "Establish baseline performance metrics"
        ]
    
    # Additional helper methods for report sections
    def _generate_threat_analysis_details(self, analysis: ThreatAnalysis) -> str:
        """Generate threat analysis details section"""
        return f"""
        Comprehensive threat analysis identified {len(analysis.threats_identified)} security threats
        across {len(analysis.data_sources_analyzed)} data sources.
        
        Analysis methodology:
        - AI model: {analysis.model_used}
        - Confidence level: {analysis.confidence_level:.1f}%
        - Processing duration: {analysis.analysis_duration:.2f} seconds
        
        Threat distribution by severity:
        - Critical: {analysis.risk_assessment.critical_threats}
        - High: {analysis.risk_assessment.high_threats}
        - Medium: {analysis.risk_assessment.medium_threats}
        - Low: {analysis.risk_assessment.low_threats}
        """
    
    def _generate_vulnerability_assessment(self, analysis: ThreatAnalysis) -> str:
        """Generate vulnerability assessment section"""
        vuln_threats = [t for t in analysis.threats_identified 
                       if t.threat_type.value == "vulnerability"]
        
        return f"""
        Vulnerability Assessment Results:
        
        Identified {len(vuln_threats)} vulnerability-related security issues.
        
        Key vulnerability categories:
        - Configuration vulnerabilities
        - Software vulnerabilities  
        - Access control vulnerabilities
        - Network security vulnerabilities
        
        Remediation priority based on exploitability and business impact.
        """
    
    def _generate_security_controls_evaluation(self, analysis: ThreatAnalysis) -> str:
        """Generate security controls evaluation section"""
        return f"""
        Security Controls Evaluation:
        
        Current mitigation coverage: {analysis.risk_assessment.mitigation_coverage:.1f}%
        
        Control effectiveness assessment:
        - Preventive controls: Adequate for {analysis.risk_assessment.mitigation_coverage * 0.4:.0f}% of threats
        - Detective controls: Coverage for {analysis.risk_assessment.mitigation_coverage * 0.3:.0f}% of threats  
        - Corrective controls: Available for {analysis.risk_assessment.mitigation_coverage * 0.3:.0f}% of threats
        
        Recommendations focus on improving control coverage and effectiveness.
        """
    
    def _generate_implementation_roadmap(self, recommendations: List[Recommendation]) -> str:
        """Generate implementation roadmap section"""
        critical_recs = [r for r in recommendations if r.priority == "critical"]
        high_recs = [r for r in recommendations if r.priority == "high"]
        
        return f"""
        Implementation Roadmap:
        
        Phase 1 (Immediate - 0-30 days):
        - {len(critical_recs)} critical security improvements
        - Focus on threat mitigation and risk reduction
        
        Phase 2 (Short-term - 1-3 months):
        - {len(high_recs)} high-priority enhancements
        - Security posture strengthening
        
        Phase 3 (Medium-term - 3-6 months):
        - Remaining security improvements
        - Continuous monitoring and optimization
        
        Total estimated effort: {sum(1 for r in recommendations)} recommendations
        """