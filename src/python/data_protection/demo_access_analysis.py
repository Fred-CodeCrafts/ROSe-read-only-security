"""
Demonstration of Access Pattern Analysis and Blast Radius Assessment

This script demonstrates the comprehensive security intelligence reporting
and automated security posture assessment capabilities.
"""

import datetime
import random
from typing import List
from .access_analyzer import AccessPatternAnalyzer, BlastRadiusAnalyzer
from .models import AccessPattern


def generate_sample_access_patterns(num_patterns: int = 100) -> List[AccessPattern]:
    """Generate sample access patterns for demonstration"""
    users = [f"user_{i:03d}" for i in range(1, 21)]  # 20 users
    resources = [
        "web_server", "database", "api_gateway", "auth_service", 
        "payment_service", "user_store", "session_store", "backup_service",
        "monitoring", "cache", "rate_limiter", "external_payment_api"
    ]
    actions = [
        "read", "write", "create", "delete", "modify", "admin", 
        "configure", "manage", "access", "view", "update"
    ]
    
    patterns = []
    base_time = datetime.datetime.now() - datetime.timedelta(days=7)
    
    for i in range(num_patterns):
        # Create realistic access patterns with some anomalies
        user_id = random.choice(users)
        resource = random.choice(resources)
        action = random.choice(actions)
        
        # Add time variation
        time_offset = random.randint(0, 7 * 24 * 60)  # Up to 7 days in minutes
        timestamp = base_time + datetime.timedelta(minutes=time_offset)
        
        # Generate IP addresses (some users have multiple IPs)
        if random.random() < 0.1:  # 10% chance of different IP
            source_ip = f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
        else:
            source_ip = f"192.168.1.{hash(user_id) % 254 + 1}"
        
        # Add some failures (5% failure rate, higher for some users)
        if user_id in ["user_005", "user_013"]:  # High-risk users
            success = random.random() > 0.3  # 30% failure rate
        else:
            success = random.random() > 0.05  # 5% failure rate
        
        # Calculate risk score based on patterns
        risk_score = 0.0
        if not success:
            risk_score += 0.3
        if timestamp.hour >= 22 or timestamp.hour <= 6:  # Unusual hours
            risk_score += 0.2
        if action in ["delete", "admin", "configure"]:  # Privileged actions
            risk_score += 0.3
        
        pattern = AccessPattern(
            user_id=user_id,
            resource=resource,
            action=action,
            timestamp=timestamp,
            source_ip=source_ip,
            success=success,
            risk_score=min(risk_score, 1.0)
        )
        patterns.append(pattern)
    
    return patterns


def demonstrate_access_analysis():
    """Demonstrate access pattern analysis capabilities"""
    print("=== Access Pattern Analysis Demonstration ===\n")
    
    # Generate sample data
    access_patterns = generate_sample_access_patterns(150)
    print(f"Generated {len(access_patterns)} sample access patterns")
    
    # Initialize analyzer
    analyzer = AccessPatternAnalyzer()
    
    # Perform analysis
    print("\nPerforming access pattern analysis...")
    analysis_report = analyzer.analyze_access_patterns(access_patterns)
    
    # Display results
    print(f"\nAnalysis Results:")
    print(f"- Total access events: {analysis_report['total_access_events']}")
    print(f"- Unique users: {analysis_report['unique_users']}")
    print(f"- Overall success rate: {analysis_report['system_insights']['overall_success_rate']:.2%}")
    print(f"- High-risk users: {analysis_report['system_insights']['high_risk_users']}")
    print(f"- Average user risk score: {analysis_report['system_insights']['average_user_risk_score']:.3f}")
    
    # Show top accessed resources
    print(f"\nTop 5 Most Accessed Resources:")
    for resource, count in analysis_report['system_insights']['most_accessed_resources'][:5]:
        print(f"  - {resource}: {count} accesses")
    
    # Show recommendations
    print(f"\nSecurity Recommendations ({len(analysis_report['recommendations'])}):")
    for i, rec in enumerate(analysis_report['recommendations'][:3], 1):
        print(f"  {i}. User {rec.user_id}: {rec.justification}")
    
    return analysis_report


def demonstrate_blast_radius_analysis():
    """Demonstrate blast radius assessment capabilities"""
    print("\n=== Blast Radius Assessment Demonstration ===\n")
    
    # Initialize analyzer
    blast_analyzer = BlastRadiusAnalyzer()
    
    # Test different incident scenarios
    scenarios = [
        ("web_server", "us-east-1", "prod-account", "medium"),
        ("database", "us-west-2", "prod-account", "high"),
        ("auth_service", "eu-west-1", "staging-account", "critical"),
        ("payment_service", "us-east-1", "prod-account", "high"),
    ]
    
    assessments = []
    
    for service, region, account, severity in scenarios:
        print(f"Assessing blast radius for {service} incident ({severity} severity)...")
        
        assessment = blast_analyzer.assess_blast_radius(
            incident_service=service,
            incident_region=region,
            incident_account=account,
            severity=severity
        )
        
        assessments.append(assessment)
        
        print(f"  - Affected services: {len(assessment.affected_services)}")
        print(f"  - Affected regions: {len(assessment.affected_regions)}")
        print(f"  - Impact score: {assessment.impact_score:.2f}")
        print(f"  - Risk level: {assessment.risk_level}")
        print(f"  - Estimated recovery: {assessment.estimated_recovery_time}")
        print(f"  - Containment recommendations: {len(assessment.containment_recommendations)}")
        print()
    
    return assessments


def demonstrate_security_posture_assessment(access_report, blast_assessments):
    """Demonstrate comprehensive security posture assessment"""
    print("=== Security Posture Assessment ===\n")
    
    blast_analyzer = BlastRadiusAnalyzer()
    
    # Generate comprehensive security posture assessment
    posture = blast_analyzer.generate_security_posture_assessment(
        access_analysis=access_report,
        blast_radius_assessments=blast_assessments
    )
    
    print(f"Overall Security Score: {posture.overall_score:.2f}/1.0")
    print(f"Risk Level: {posture.risk_level.upper()}")
    
    print(f"\nCritical Findings ({len(posture.critical_findings)}):")
    for finding in posture.critical_findings:
        print(f"  - {finding}")
    
    print(f"\nRecommendations ({len(posture.recommendations)}):")
    for rec in posture.recommendations:
        print(f"  - {rec}")
    
    print(f"\nImprovement Areas ({len(posture.improvement_areas)}):")
    for area in posture.improvement_areas:
        print(f"  - {area}")
    
    print(f"\nCompliance Status:")
    for requirement, status in posture.compliance_status.items():
        status_icon = "✓" if status else "✗"
        print(f"  {status_icon} {requirement.replace('_', ' ').title()}")
    
    return posture


def main():
    """Main demonstration function"""
    print("AI-Assisted Cybersecurity Analysis & Governance Platform")
    print("Data Protection and Access Analysis Demonstration")
    print("=" * 60)
    
    try:
        # Demonstrate access pattern analysis
        access_report = demonstrate_access_analysis()
        
        # Demonstrate blast radius assessment
        blast_assessments = demonstrate_blast_radius_analysis()
        
        # Demonstrate comprehensive security posture assessment
        security_posture = demonstrate_security_posture_assessment(
            access_report, blast_assessments
        )
        
        print("\n" + "=" * 60)
        print("Demonstration completed successfully!")
        print(f"Analyzed {access_report['total_access_events']} access events")
        print(f"Assessed {len(blast_assessments)} incident scenarios")
        print(f"Generated comprehensive security posture assessment")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        raise


if __name__ == "__main__":
    main()