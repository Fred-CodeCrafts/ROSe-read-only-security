"""
Tests for the Instant Insights Generator module.

Tests multi-audience report generation and visualization creation.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock

from aws_bedrock_athena_ai.reasoning_engine.models import (
    ThreatAnalysis, Threat, Recommendation, RiskAssessment, 
    ThreatSeverity, ThreatType, RiskLevel, Evidence, Pattern
)
from aws_bedrock_athena_ai.insights.instant_insights_generator import InstantInsightsGenerator
from aws_bedrock_athena_ai.insights.models import AudienceType


@pytest.fixture
def sample_threat_analysis():
    """Create sample threat analysis for testing"""
    
    # Create sample threats
    threats = [
        Threat(
            threat_id="T001",
            threat_type=ThreatType.VULNERABILITY,
            severity=ThreatSeverity.CRITICAL,
            title="Critical SQL Injection Vulnerability",
            description="SQL injection vulnerability in user authentication system",
            affected_systems=["web-app-01", "database-01"],
            indicators=["sql_injection", "authentication_bypass"],
            timeline=[],
            evidence=[
                Evidence(
                    source="security_scan",
                    timestamp=datetime.now(),
                    description="Automated security scan detected SQL injection",
                    raw_data={"scanner": "test", "severity": "critical"},
                    confidence=0.95
                )
            ],
            confidence=0.95,
            first_seen=datetime.now() - timedelta(hours=2),
            last_seen=datetime.now()
        ),
        Threat(
            threat_id="T002",
            threat_type=ThreatType.CONFIGURATION_ISSUE,
            severity=ThreatSeverity.HIGH,
            title="Weak Password Policy",
            description="Password policy does not meet security standards",
            affected_systems=["active-directory"],
            indicators=["weak_passwords", "policy_violation"],
            timeline=[],
            evidence=[],
            confidence=0.85
        )
    ]
    
    # Create sample recommendations
    recommendations = [
        Recommendation(
            recommendation_id="R001",
            priority="critical",
            category="vulnerability_management",
            title="Patch SQL Injection Vulnerability",
            description="Implement input validation and parameterized queries",
            implementation_steps=[
                "Review affected code",
                "Implement parameterized queries",
                "Deploy security patches",
                "Conduct security testing"
            ],
            estimated_effort="1 week",
            business_impact="Prevents potential data breach and regulatory violations",
            related_threats=["T001"],
            cost_analysis={"estimated_cost": 5000},
            cost_benefit_ratio=10.0
        ),
        Recommendation(
            recommendation_id="R002",
            priority="high",
            category="access_control",
            title="Strengthen Password Policy",
            description="Update password policy to meet security standards",
            implementation_steps=[
                "Review current policy",
                "Update policy requirements",
                "Implement policy enforcement",
                "User training"
            ],
            estimated_effort="2 weeks",
            business_impact="Reduces risk of credential-based attacks",
            related_threats=["T002"],
            cost_analysis={"estimated_cost": 2000},
            cost_benefit_ratio=5.0
        )
    ]
    
    # Create risk assessment
    risk_assessment = RiskAssessment(
        overall_risk_score=7.5,
        risk_level=RiskLevel.HIGH,
        critical_threats=1,
        high_threats=1,
        medium_threats=0,
        low_threats=0,
        risk_factors=["unpatched_vulnerabilities", "weak_access_controls"],
        mitigation_coverage=65.0,
        trend="stable"
    )
    
    # Create threat analysis
    return ThreatAnalysis(
        analysis_id="A001",
        timestamp=datetime.now(),
        threats_identified=threats,
        risk_assessment=risk_assessment,
        patterns=[],
        recommendations=recommendations,
        confidence_level=0.90,
        data_sources_analyzed=["security_logs", "vulnerability_scans"],
        analysis_duration=45.2,
        model_used="claude-3-sonnet",
        summary="Security analysis identified critical vulnerabilities requiring immediate attention",
        executive_summary="Critical security issues found that require immediate remediation to prevent potential data breaches"
    )


class TestInstantInsightsGenerator:
    """Test cases for InstantInsightsGenerator"""
    
    def test_initialization(self):
        """Test InstantInsightsGenerator initialization"""
        generator = InstantInsightsGenerator()
        
        assert generator.report_generator is not None
        assert generator.visualization_generator is not None
        assert generator.action_plan_generator is not None
    
    def test_generate_executive_summary(self, sample_threat_analysis):
        """Test executive summary generation"""
        generator = InstantInsightsGenerator()
        
        executive_report = generator.generate_executive_summary(sample_threat_analysis)
        
        assert executive_report is not None
        assert executive_report.title is not None
        assert executive_report.executive_summary is not None
        assert executive_report.risk_score == 7.5
        assert executive_report.critical_issues == 2  # 1 critical + 1 high
        assert len(executive_report.key_findings) > 0
        assert len(executive_report.recommendations_summary) > 0
        assert len(executive_report.sections) > 0
    
    def test_create_technical_details(self, sample_threat_analysis):
        """Test technical report generation"""
        generator = InstantInsightsGenerator()
        
        technical_report = generator.create_technical_details(sample_threat_analysis)
        
        assert technical_report is not None
        assert technical_report.title is not None
        assert technical_report.technical_summary is not None
        assert len(technical_report.detailed_findings) == 2  # 2 threats
        assert len(technical_report.threat_details) == 2
        assert len(technical_report.remediation_steps) == 2  # 2 recommendations
        assert technical_report.system_analysis is not None
        assert len(technical_report.sections) > 0
    
    def test_build_action_plan(self, sample_threat_analysis):
        """Test action plan generation"""
        generator = InstantInsightsGenerator()
        
        action_plan = generator.build_action_plan(
            sample_threat_analysis.recommendations, 
            sample_threat_analysis
        )
        
        assert action_plan is not None
        assert action_plan.title is not None
        assert action_plan.total_items == 2
        assert action_plan.critical_items == 1
        assert action_plan.high_priority_items == 1
        assert len(action_plan.action_items) == 2
        assert len(action_plan.milestones) > 0
        assert action_plan.total_cost_estimate is not None
        assert action_plan.expected_roi is not None
    
    def test_generate_visualizations_executive(self, sample_threat_analysis):
        """Test visualization generation for executive audience"""
        generator = InstantInsightsGenerator()
        
        visualizations = generator.generate_visualizations(
            sample_threat_analysis, 
            AudienceType.EXECUTIVE
        )
        
        assert len(visualizations) >= 2  # At least risk dashboard and security posture
        
        # Check risk dashboard
        risk_dashboard = next((v for v in visualizations if "Risk Dashboard" in v.title), None)
        assert risk_dashboard is not None
        assert risk_dashboard.audience == AudienceType.EXECUTIVE
        
        # Check security posture chart
        posture_chart = next((v for v in visualizations if "Security Posture" in v.title), None)
        assert posture_chart is not None
    
    def test_generate_visualizations_technical(self, sample_threat_analysis):
        """Test visualization generation for technical audience"""
        generator = InstantInsightsGenerator()
        
        visualizations = generator.generate_visualizations(
            sample_threat_analysis, 
            AudienceType.TECHNICAL
        )
        
        # Technical audience should get more visualizations
        assert len(visualizations) >= 4
        
        # Should include threat timeline and trend analysis
        timeline_viz = next((v for v in visualizations if "Timeline" in v.title), None)
        assert timeline_viz is not None
        
        trend_viz = next((v for v in visualizations if "Trend" in v.title), None)
        assert trend_viz is not None
    
    def test_create_comprehensive_insights_package(self, sample_threat_analysis):
        """Test comprehensive insights package generation"""
        generator = InstantInsightsGenerator()
        
        insights_package = generator.create_comprehensive_insights_package(
            sample_threat_analysis
        )
        
        assert insights_package is not None
        assert insights_package["analysis_id"] == "A001"
        assert "summary" in insights_package
        assert "audiences" in insights_package
        assert "unified_action_plan" in insights_package
        
        # Check summary
        summary = insights_package["summary"]
        assert summary["total_threats"] == 2
        assert summary["risk_score"] == 7.5
        assert summary["critical_issues"] == 1
        assert summary["recommendations_count"] == 2
        
        # Check audiences
        audiences = insights_package["audiences"]
        assert "executive" in audiences
        assert "technical" in audiences
        assert "compliance" in audiences
        
        # Check executive insights
        exec_insights = audiences["executive"]
        assert "report" in exec_insights
        assert "visualizations" in exec_insights
        assert len(exec_insights["visualizations"]) >= 2
        
        # Check technical insights
        tech_insights = audiences["technical"]
        assert "report" in tech_insights
        assert "action_plan" in tech_insights
        assert tech_insights["action_plan"] is not None
    
    def test_explain_security_concepts(self):
        """Test security concept explanations"""
        generator = InstantInsightsGenerator()
        
        # Test executive explanation
        exec_explanation = generator.explain_security_concepts("threat", AudienceType.EXECUTIVE)
        assert "business" in exec_explanation.lower()
        assert len(exec_explanation) > 20
        
        # Test technical explanation
        tech_explanation = generator.explain_security_concepts("threat", AudienceType.TECHNICAL)
        assert "attack" in tech_explanation.lower() or "malicious" in tech_explanation.lower()
        assert len(tech_explanation) > 20
        
        # Test unknown concept
        unknown_explanation = generator.explain_security_concepts("unknown_concept")
        assert "Security concept" in unknown_explanation
    
    def test_generate_evidence_links(self, sample_threat_analysis):
        """Test evidence link generation"""
        generator = InstantInsightsGenerator()
        
        evidence_links = generator.generate_evidence_links(sample_threat_analysis)
        
        assert evidence_links is not None
        assert "T001" in evidence_links  # Threat with evidence
        assert len(evidence_links["T001"]) > 0
        
        # Check evidence format
        evidence_entry = evidence_links["T001"][0]
        assert "security_scan" in evidence_entry
        assert "[High Confidence]" in evidence_entry  # Confidence >= 0.8


class TestReportGeneration:
    """Test specific report generation functionality"""
    
    def test_executive_report_business_focus(self, sample_threat_analysis):
        """Test that executive reports focus on business impact"""
        generator = InstantInsightsGenerator()
        
        report = generator.generate_executive_summary(sample_threat_analysis)
        
        # Check business-focused content
        assert "business" in report.business_impact.lower()
        assert report.cost_benefit_analysis is not None
        assert report.industry_benchmarks is not None
        assert len(report.next_steps) > 0
        
        # Check that technical jargon is minimized
        for finding in report.key_findings:
            # Should avoid overly technical terms
            assert not any(term in finding.lower() for term in ["sql injection", "parameterized queries"])
    
    def test_technical_report_detail_level(self, sample_threat_analysis):
        """Test that technical reports include appropriate detail"""
        generator = InstantInsightsGenerator()
        
        report = generator.create_technical_details(sample_threat_analysis)
        
        # Check technical detail level
        assert len(report.detailed_findings) == 2
        assert len(report.threat_details) == 2
        
        # Should include technical information
        technical_content = str(report.technical_recommendations)
        assert len(technical_content) > 100  # Substantial technical content
        
        # Check appendices for raw data
        assert "raw_threat_data" in report.appendices
        assert "analysis_metadata" in report.appendices


if __name__ == "__main__":
    pytest.main([__file__])