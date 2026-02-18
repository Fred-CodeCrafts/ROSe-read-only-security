"""
Demo script for the Instant Insights Generator.

This script demonstrates how to use the InstantInsightsGenerator to create
multi-audience reports, visualizations, and action plans from threat analysis.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any

from aws_bedrock_athena_ai.reasoning_engine.models import (
    ThreatAnalysis, Threat, Recommendation, RiskAssessment, 
    ThreatSeverity, ThreatType, RiskLevel, Evidence, Pattern
)
from aws_bedrock_athena_ai.insights.instant_insights_generator import InstantInsightsGenerator
from aws_bedrock_athena_ai.insights.models import AudienceType


def create_sample_analysis() -> ThreatAnalysis:
    """Create a sample threat analysis for demonstration"""
    
    # Sample threats
    threats = [
        Threat(
            threat_id="T001",
            threat_type=ThreatType.VULNERABILITY,
            severity=ThreatSeverity.CRITICAL,
            title="Critical SQL Injection in Authentication System",
            description="SQL injection vulnerability allows authentication bypass",
            affected_systems=["web-app-prod", "auth-service", "user-database"],
            indicators=["sql_injection", "authentication_bypass", "privilege_escalation"],
            timeline=[],
            evidence=[
                Evidence(
                    source="automated_security_scan",
                    timestamp=datetime.now() - timedelta(hours=1),
                    description="OWASP ZAP detected SQL injection in login endpoint",
                    raw_data={"scanner": "OWASP ZAP", "endpoint": "/api/auth/login"},
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
            title="Weak SSL/TLS Configuration",
            description="Web servers using outdated TLS versions and weak ciphers",
            affected_systems=["web-server-01", "web-server-02", "api-gateway"],
            indicators=["weak_tls", "outdated_protocols", "insecure_ciphers"],
            timeline=[],
            evidence=[],
            confidence=0.88
        ),
        Threat(
            threat_id="T003",
            threat_type=ThreatType.INSIDER_THREAT,
            severity=ThreatSeverity.MEDIUM,
            title="Excessive Administrative Privileges",
            description="Multiple users have unnecessary administrative access",
            affected_systems=["active-directory", "admin-console"],
            indicators=["privilege_escalation", "excessive_permissions"],
            timeline=[],
            evidence=[],
            confidence=0.75
        )
    ]
    
    # Sample recommendations
    recommendations = [
        Recommendation(
            recommendation_id="R001",
            priority="critical",
            category="vulnerability_management",
            title="Immediate SQL Injection Remediation",
            description="Implement parameterized queries and input validation",
            implementation_steps=[
                "Identify all SQL injection points in authentication system",
                "Implement parameterized queries for all database interactions",
                "Add comprehensive input validation and sanitization",
                "Deploy security patches to production environment",
                "Conduct penetration testing to verify fixes"
            ],
            estimated_effort="1 week",
            business_impact="Prevents potential data breach affecting 100,000+ customer records",
            related_threats=["T001"],
            cost_analysis={"estimated_cost": 8000, "resource_hours": 80},
            cost_benefit_ratio=15.0,
            compliance_frameworks=["PCI-DSS", "SOC2"]
        ),
        Recommendation(
            recommendation_id="R002",
            priority="high",
            category="infrastructure",
            title="Upgrade TLS Configuration",
            description="Update all web servers to use TLS 1.3 and strong cipher suites",
            implementation_steps=[
                "Audit current TLS configurations across all web servers",
                "Update server configurations to disable TLS 1.0/1.1",
                "Enable TLS 1.3 and configure strong cipher suites",
                "Update load balancer SSL termination settings",
                "Test compatibility with client applications"
            ],
            estimated_effort="2 weeks",
            business_impact="Ensures secure data transmission and regulatory compliance",
            related_threats=["T002"],
            cost_analysis={"estimated_cost": 5000, "resource_hours": 60},
            cost_benefit_ratio=8.0,
            compliance_frameworks=["GDPR", "HIPAA"]
        ),
        Recommendation(
            recommendation_id="R003",
            priority="medium",
            category="access_control",
            title="Implement Principle of Least Privilege",
            description="Review and reduce administrative privileges across all systems",
            implementation_steps=[
                "Conduct comprehensive privilege audit",
                "Identify users with excessive administrative access",
                "Implement role-based access control (RBAC)",
                "Remove unnecessary administrative privileges",
                "Establish regular access review procedures"
            ],
            estimated_effort="1 month",
            business_impact="Reduces insider threat risk and improves compliance posture",
            related_threats=["T003"],
            cost_analysis={"estimated_cost": 12000, "resource_hours": 120},
            cost_benefit_ratio=4.0,
            compliance_frameworks=["SOC2", "ISO27001"]
        )
    ]
    
    # Risk assessment
    risk_assessment = RiskAssessment(
        overall_risk_score=8.2,
        risk_level=RiskLevel.HIGH,
        critical_threats=1,
        high_threats=1,
        medium_threats=1,
        low_threats=0,
        risk_factors=[
            "unpatched_critical_vulnerabilities",
            "weak_encryption_protocols", 
            "excessive_administrative_privileges",
            "insufficient_access_controls"
        ],
        mitigation_coverage=45.0,
        trend="deteriorating"
    )
    
    return ThreatAnalysis(
        analysis_id="DEMO_001",
        timestamp=datetime.now(),
        threats_identified=threats,
        risk_assessment=risk_assessment,
        patterns=[],
        recommendations=recommendations,
        confidence_level=0.87,
        data_sources_analyzed=[
            "security_logs", 
            "vulnerability_scans", 
            "configuration_audits",
            "access_logs"
        ],
        analysis_duration=127.5,
        model_used="claude-3-sonnet",
        summary="Security analysis identified critical vulnerabilities and configuration issues requiring immediate attention",
        executive_summary="Critical security vulnerabilities discovered that pose immediate risk to business operations and customer data. Immediate action required to prevent potential data breach."
    )


def demo_executive_insights():
    """Demonstrate executive-focused insights generation"""
    print("=== EXECUTIVE INSIGHTS DEMO ===\n")
    
    # Create sample analysis
    analysis = create_sample_analysis()
    generator = InstantInsightsGenerator()
    
    # Generate executive summary
    executive_report = generator.generate_executive_summary(analysis)
    
    print("EXECUTIVE SUMMARY:")
    print(f"Title: {executive_report.title}")
    print(f"Risk Score: {executive_report.risk_score}/10.0")
    print(f"Critical Issues: {executive_report.critical_issues}")
    print(f"\nBusiness Impact: {executive_report.business_impact}")
    
    print(f"\nKey Findings:")
    for i, finding in enumerate(executive_report.key_findings, 1):
        print(f"  {i}. {finding}")
    
    print(f"\nRecommendations Summary:")
    for i, rec in enumerate(executive_report.recommendations_summary, 1):
        print(f"  {i}. {rec}")
    
    print(f"\nNext Steps:")
    for i, step in enumerate(executive_report.next_steps, 1):
        print(f"  {i}. {step}")
    
    # Generate visualizations
    visualizations = generator.generate_visualizations(analysis, AudienceType.EXECUTIVE)
    
    print(f"\nGenerated {len(visualizations)} executive visualizations:")
    for viz in visualizations:
        print(f"  - {viz.title} ({viz.viz_type.value})")


def demo_technical_insights():
    """Demonstrate technical-focused insights generation"""
    print("\n=== TECHNICAL INSIGHTS DEMO ===\n")
    
    analysis = create_sample_analysis()
    generator = InstantInsightsGenerator()
    
    # Generate technical report
    technical_report = generator.create_technical_details(analysis)
    
    print("TECHNICAL ANALYSIS:")
    print(f"Title: {technical_report.title}")
    print(f"Analysis Duration: {analysis.analysis_duration:.1f} seconds")
    print(f"Model Used: {analysis.model_used}")
    print(f"Confidence Level: {analysis.confidence_level:.1%}")
    
    print(f"\nDetailed Findings ({len(technical_report.detailed_findings)} threats):")
    for finding in technical_report.detailed_findings:
        print(f"  - {finding['title']} (Severity: {finding['severity']})")
        print(f"    Confidence: {finding['confidence']:.1%}")
        print(f"    Affected Systems: {', '.join(finding['affected_systems'][:3])}")
    
    print(f"\nRemediation Steps ({len(technical_report.remediation_steps)} recommendations):")
    for step in technical_report.remediation_steps:
        print(f"  - {step['title']} (Priority: {step['priority']})")
        print(f"    Effort: {step['estimated_effort']}")
    
    # Generate action plan
    action_plan = generator.build_action_plan(analysis.recommendations, analysis)
    
    print(f"\nACTION PLAN:")
    print(f"Total Items: {action_plan.total_items}")
    print(f"Critical Items: {action_plan.critical_items}")
    print(f"Estimated Timeline: {action_plan.estimated_timeline}")
    print(f"Total Cost Estimate: ${action_plan.total_cost_estimate:,.0f}")
    print(f"Expected ROI: {action_plan.expected_roi:.1f}x")
    
    print(f"\nMilestones ({len(action_plan.milestones)}):")
    for milestone in action_plan.milestones:
        print(f"  - {milestone['name']}")
        print(f"    Target: {milestone['target_date'][:10]}")


def demo_comprehensive_package():
    """Demonstrate comprehensive insights package for all audiences"""
    print("\n=== COMPREHENSIVE INSIGHTS PACKAGE DEMO ===\n")
    
    analysis = create_sample_analysis()
    generator = InstantInsightsGenerator()
    
    # Generate comprehensive package
    insights_package = generator.create_comprehensive_insights_package(analysis)
    
    print("COMPREHENSIVE INSIGHTS PACKAGE:")
    print(f"Analysis ID: {insights_package['analysis_id']}")
    print(f"Generated: {insights_package['timestamp'][:19]}")
    
    summary = insights_package['summary']
    print(f"\nSUMMARY:")
    print(f"  Total Threats: {summary['total_threats']}")
    print(f"  Risk Score: {summary['risk_score']}/10.0")
    print(f"  Critical Issues: {summary['critical_issues']}")
    print(f"  Recommendations: {summary['recommendations_count']}")
    
    print(f"\nAUDIENCE-SPECIFIC INSIGHTS:")
    for audience_name, audience_data in insights_package['audiences'].items():
        print(f"\n  {audience_name.upper()}:")
        print(f"    Report: {type(audience_data['report']).__name__}")
        print(f"    Visualizations: {len(audience_data['visualizations'])}")
        if audience_data['action_plan']:
            print(f"    Action Plan: {audience_data['action_plan'].total_items} items")
    
    # Show unified action plan
    unified_plan = insights_package['unified_action_plan']
    print(f"\nUNIFIED ACTION PLAN:")
    print(f"  Total Items: {unified_plan.total_items}")
    print(f"  Timeline: {unified_plan.estimated_timeline}")
    print(f"  Success Metrics: {len(unified_plan.success_metrics)}")


def demo_security_concepts():
    """Demonstrate security concept explanations for different audiences"""
    print("\n=== SECURITY CONCEPT EXPLANATIONS DEMO ===\n")
    
    generator = InstantInsightsGenerator()
    concepts = ["threat", "vulnerability", "risk_score", "mitigation"]
    
    for concept in concepts:
        print(f"CONCEPT: {concept.upper()}")
        
        for audience in [AudienceType.EXECUTIVE, AudienceType.TECHNICAL, AudienceType.COMPLIANCE]:
            explanation = generator.explain_security_concepts(concept, audience)
            print(f"  {audience.value}: {explanation}")
        print()


def main():
    """Run all demos"""
    print("AI SECURITY ANALYST - INSTANT INSIGHTS GENERATOR DEMO")
    print("=" * 60)
    
    try:
        demo_executive_insights()
        demo_technical_insights()
        demo_comprehensive_package()
        demo_security_concepts()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("\nThe Instant Insights Generator successfully demonstrated:")
        print("✓ Multi-audience report generation (Executive, Technical, Compliance)")
        print("✓ Comprehensive visualization creation")
        print("✓ Prioritized action plan development")
        print("✓ Audience-appropriate security concept explanations")
        print("✓ Evidence linking and citation")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()