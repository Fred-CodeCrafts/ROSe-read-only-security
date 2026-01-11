"""
Property-Based Tests for Access Analysis

Tests Property 11: Access Pattern Analysis
Tests Property 12: Blast Radius Assessment
Validates Requirements 2.5, 2.6
"""

import pytest
from hypothesis import given, strategies as st, settings, example
from hypothesis.strategies import composite
import datetime
from typing import List

from src.python.data_protection.access_analyzer import AccessPatternAnalyzer, BlastRadiusAnalyzer
from src.python.data_protection.models import AccessPattern


# Test data generators
@composite
def access_pattern_strategy(draw):
    """Generate realistic access patterns for testing"""
    user_id = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789_', min_size=5, max_size=20))
    resource = draw(st.sampled_from([
        'web_server', 'database', 'api_gateway', 'auth_service', 
        'payment_service', 'user_store', 'session_store', 'backup_service'
    ]))
    action = draw(st.sampled_from([
        'read', 'write', 'create', 'delete', 'modify', 'admin', 'configure', 'manage'
    ]))
    
    # Generate timestamp within last 30 days
    base_time = datetime.datetime.now() - datetime.timedelta(days=30)
    offset_minutes = draw(st.integers(min_value=0, max_value=30 * 24 * 60))
    timestamp = base_time + datetime.timedelta(minutes=offset_minutes)
    
    source_ip = f"192.168.{draw(st.integers(min_value=1, max_value=255))}.{draw(st.integers(min_value=1, max_value=255))}"
    success = draw(st.booleans())
    risk_score = draw(st.floats(min_value=0.0, max_value=1.0))
    
    return AccessPattern(
        user_id=user_id,
        resource=resource,
        action=action,
        timestamp=timestamp,
        source_ip=source_ip,
        success=success,
        risk_score=risk_score
    )


@composite
def incident_scenario_strategy(draw):
    """Generate incident scenarios for blast radius testing"""
    service = draw(st.sampled_from([
        'web_server', 'database', 'api_gateway', 'auth_service', 'payment_service'
    ]))
    region = draw(st.sampled_from(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']))
    account = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789-', min_size=10, max_size=20))
    severity = draw(st.sampled_from(['low', 'medium', 'high', 'critical']))
    
    return service, region, account, severity


class TestAccessAnalysisProperties:
    """Property-based tests for access pattern analysis and blast radius assessment"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.access_analyzer = AccessPatternAnalyzer()
        self.blast_analyzer = BlastRadiusAnalyzer()
    
    @given(st.lists(access_pattern_strategy(), min_size=1, max_size=50))
    @settings(max_examples=100)
    @example([AccessPattern(
        user_id="test_user",
        resource="web_server", 
        action="read",
        timestamp=datetime.datetime.now(),
        source_ip="192.168.1.1",
        success=True,
        risk_score=0.5
    )])
    def test_property_11_access_pattern_analysis(self, access_patterns: List[AccessPattern]):
        """
        Property 11: Access Pattern Analysis
        
        For any list of access patterns, the AccessPatternAnalyzer should
        generate comprehensive analysis with least-privilege recommendations,
        risk scoring, and security intelligence that accurately reflects
        the input patterns and provides actionable insights.
        
        **Validates: Requirements 2.5**
        """
        # Perform access pattern analysis
        analysis_report = self.access_analyzer.analyze_access_patterns(access_patterns)
        
        # Property: Analysis should process all input patterns
        assert analysis_report['total_access_events'] == len(access_patterns), \
            "Should analyze all provided access patterns"
        
        # Property: Should identify unique users correctly
        unique_users = set(pattern.user_id for pattern in access_patterns)
        assert analysis_report['unique_users'] == len(unique_users), \
            "Should correctly count unique users"
        
        # Property: System insights should be consistent with input data
        system_insights = analysis_report['system_insights']
        assert isinstance(system_insights, dict), "System insights should be a dictionary"
        assert 'overall_success_rate' in system_insights, "Should calculate overall success rate"
        assert 0.0 <= system_insights['overall_success_rate'] <= 1.0, \
            "Success rate should be between 0 and 1"
        
        # Property: Success rate should match actual success rate
        successful_accesses = sum(1 for p in access_patterns if p.success)
        expected_success_rate = successful_accesses / len(access_patterns)
        assert abs(system_insights['overall_success_rate'] - expected_success_rate) < 0.001, \
            "Calculated success rate should match actual success rate"
        
        # Property: User analyses should exist for all users
        user_analyses = analysis_report['user_analyses']
        assert len(user_analyses) == len(unique_users), \
            "Should have analysis for each unique user"
        
        for user_id in unique_users:
            assert user_id in user_analyses, f"Should have analysis for user {user_id}"
            user_analysis = user_analyses[user_id]
            
            # Property: User analysis should have required fields
            required_fields = ['total_accesses', 'successful_accesses', 'failed_accesses', 
                             'success_rate', 'risk_score', 'privilege_level']
            for field in required_fields:
                assert field in user_analysis, f"User analysis should have {field} field"
            
            # Property: User access counts should be consistent
            user_patterns = [p for p in access_patterns if p.user_id == user_id]
            assert user_analysis['total_accesses'] == len(user_patterns), \
                f"User {user_id} access count should match patterns"
            
            successful_user_accesses = sum(1 for p in user_patterns if p.success)
            assert user_analysis['successful_accesses'] == successful_user_accesses, \
                f"User {user_id} successful access count should match"
        
        # Property: Recommendations should be actionable
        recommendations = analysis_report['recommendations']
        assert isinstance(recommendations, list), "Recommendations should be a list"
        
        for rec in recommendations:
            assert hasattr(rec, 'user_id'), "Recommendation should have user_id"
            assert hasattr(rec, 'justification'), "Recommendation should have justification"
            assert hasattr(rec, 'risk_reduction'), "Recommendation should have risk_reduction"
            assert 0.0 <= rec.risk_reduction <= 1.0, "Risk reduction should be between 0 and 1"
        
        # Property: Risk summary should be consistent
        risk_summary = analysis_report['risk_summary']
        if risk_summary:  # Only check if risk summary exists
            assert 'average_risk_score' in risk_summary, "Should have average risk score"
            assert 0.0 <= risk_summary['average_risk_score'] <= 1.0, \
                "Average risk score should be between 0 and 1"
    
    @given(incident_scenario_strategy())
    @settings(max_examples=100)
    @example(("web_server", "us-east-1", "test-account", "medium"))
    def test_property_12_blast_radius_assessment(self, incident_scenario):
        """
        Property 12: Blast Radius Assessment
        
        For any security incident scenario (service, region, account, severity),
        the BlastRadiusAnalyzer should generate comprehensive impact assessment
        with containment analysis, impact prediction, and recovery recommendations
        that scale appropriately with incident severity.
        
        **Validates: Requirements 2.6**
        """
        service, region, account, severity = incident_scenario
        
        # Perform blast radius assessment
        assessment = self.blast_analyzer.assess_blast_radius(
            incident_service=service,
            incident_region=region,
            incident_account=account,
            severity=severity
        )
        
        # Property: Assessment should include the incident service
        assert service in assessment.affected_services, \
            "Incident service should be in affected services"
        
        # Property: Assessment should include the incident region
        assert region in assessment.affected_regions, \
            "Incident region should be in affected regions"
        
        # Property: Assessment should include the incident account
        assert account in assessment.affected_accounts, \
            "Incident account should be in affected accounts"
        
        # Property: Impact score should be valid
        assert 0.0 <= assessment.impact_score <= 1.0, \
            "Impact score should be between 0 and 1"
        
        # Property: Risk level should be valid
        valid_risk_levels = ['low', 'medium', 'high', 'critical']
        assert assessment.risk_level in valid_risk_levels, \
            f"Risk level should be one of {valid_risk_levels}"
        
        # Property: Higher severity should generally result in higher impact
        if severity == 'critical':
            assert assessment.impact_score >= 0.6, \
                "Critical incidents should have high impact scores"
            assert len(assessment.affected_services) >= 3, \
                "Critical incidents should affect multiple services"
        elif severity == 'high':
            assert assessment.impact_score >= 0.4, \
                "High severity incidents should have significant impact"
        
        # Property: Containment recommendations should be provided
        assert isinstance(assessment.containment_recommendations, list), \
            "Should provide containment recommendations"
        assert len(assessment.containment_recommendations) > 0, \
            "Should have at least one containment recommendation"
        
        # Property: Recovery time should be reasonable string format
        assert isinstance(assessment.estimated_recovery_time, str), \
            "Recovery time should be a string"
        assert len(assessment.estimated_recovery_time) > 0, \
            "Recovery time should not be empty"
        
        # Property: More severe incidents should have longer recovery times
        if severity == 'critical':
            # Critical incidents should mention days or many hours
            assert any(word in assessment.estimated_recovery_time.lower() 
                      for word in ['day', 'days', '24', '48']), \
                "Critical incidents should have longer recovery times"
        
        # Property: Affected services should be reasonable
        assert len(assessment.affected_services) >= 1, \
            "Should affect at least the incident service"
        assert len(assessment.affected_services) <= 20, \
            "Should not affect unreasonably many services"
        
        # Property: Affected regions should be reasonable
        assert len(assessment.affected_regions) >= 1, \
            "Should affect at least the incident region"
        assert len(assessment.affected_regions) <= 10, \
            "Should not affect unreasonably many regions"
    
    @given(st.lists(access_pattern_strategy(), min_size=5, max_size=30),
           st.lists(incident_scenario_strategy(), min_size=1, max_size=5))
    @settings(max_examples=50)
    def test_property_11_12_integrated_security_posture(self, access_patterns, incident_scenarios):
        """
        Properties 11 & 12: Integrated Security Posture Assessment
        
        For any combination of access patterns and incident scenarios,
        the integrated security posture assessment should provide
        comprehensive security intelligence that combines access analysis
        and blast radius assessment into actionable security insights.
        
        **Validates: Requirements 2.5, 2.6**
        """
        # Perform access analysis
        access_report = self.access_analyzer.analyze_access_patterns(access_patterns)
        
        # Perform blast radius assessments
        blast_assessments = []
        for service, region, account, severity in incident_scenarios:
            assessment = self.blast_analyzer.assess_blast_radius(service, region, account, severity)
            blast_assessments.append(assessment)
        
        # Generate integrated security posture assessment
        posture = self.blast_analyzer.generate_security_posture_assessment(
            access_analysis=access_report,
            blast_radius_assessments=blast_assessments
        )
        
        # Property: Overall score should be valid
        assert 0.0 <= posture.overall_score <= 1.0, \
            "Overall security score should be between 0 and 1"
        
        # Property: Risk level should be consistent with score
        if posture.overall_score >= 0.8:
            assert posture.risk_level == 'low', \
                "High scores should correspond to low risk"
        elif posture.overall_score <= 0.4:
            assert posture.risk_level in ['high', 'critical'], \
                "Low scores should correspond to high/critical risk"
        
        # Property: Should provide findings and recommendations
        assert isinstance(posture.critical_findings, list), \
            "Should provide critical findings"
        assert isinstance(posture.recommendations, list), \
            "Should provide recommendations"
        assert isinstance(posture.improvement_areas, list), \
            "Should provide improvement areas"
        
        # Property: Compliance status should be comprehensive
        assert isinstance(posture.compliance_status, dict), \
            "Should provide compliance status"
        
        expected_compliance_areas = ['access_logging', 'risk_assessment', 'incident_response', 'least_privilege']
        for area in expected_compliance_areas:
            assert area in posture.compliance_status, \
                f"Should assess {area} compliance"
            assert isinstance(posture.compliance_status[area], bool), \
                f"Compliance status for {area} should be boolean"
        
        # Property: High-risk scenarios should generate findings
        critical_assessments = [a for a in blast_assessments if a.risk_level == 'critical']
        if critical_assessments:
            assert len(posture.critical_findings) > 0, \
                "Critical blast radius scenarios should generate critical findings"
        
        # Property: High-risk users should generate findings
        high_risk_users = access_report.get('system_insights', {}).get('high_risk_users', 0)
        if high_risk_users > 0:
            assert any('high-risk users' in finding.lower() for finding in posture.critical_findings), \
                "High-risk users should generate critical findings"
    
    @given(st.lists(access_pattern_strategy(), min_size=10, max_size=100))
    @settings(max_examples=50)
    def test_property_11_least_privilege_recommendations(self, access_patterns):
        """
        Property 11: Least-Privilege Recommendations
        
        For any set of access patterns, the system should generate
        appropriate least-privilege recommendations that reduce risk
        while maintaining necessary access for legitimate operations.
        
        **Validates: Requirements 2.5**
        """
        # Perform analysis
        analysis_report = self.access_analyzer.analyze_access_patterns(access_patterns)
        recommendations = analysis_report['recommendations']
        
        # Property: Recommendations should target risk reduction
        for rec in recommendations:
            assert rec.risk_reduction > 0.0, \
                "All recommendations should provide positive risk reduction"
            assert rec.risk_reduction <= 1.0, \
                "Risk reduction should not exceed 100%"
        
        # Property: High-risk users should get recommendations
        user_analyses = analysis_report['user_analyses']
        high_risk_users = [uid for uid, analysis in user_analyses.items() 
                          if analysis['risk_score'] > 0.7]
        
        if high_risk_users:
            recommended_users = set(rec.user_id for rec in recommendations)
            # At least some high-risk users should get recommendations
            assert len(recommended_users.intersection(high_risk_users)) > 0, \
                "High-risk users should receive recommendations"
        
        # Property: Recommendations should be specific and actionable
        for rec in recommendations:
            assert len(rec.justification) > 10, \
                "Recommendations should have meaningful justification"
            assert rec.user_id in user_analyses, \
                "Recommendations should target analyzed users"
    
    @given(st.lists(incident_scenario_strategy(), min_size=2, max_size=10))
    @settings(max_examples=50)
    def test_property_12_containment_scaling(self, incident_scenarios):
        """
        Property 12: Containment Recommendation Scaling
        
        For any set of incident scenarios, containment recommendations
        should scale appropriately with incident severity and scope,
        providing more comprehensive containment for higher-impact incidents.
        
        **Validates: Requirements 2.6**
        """
        assessments = []
        for service, region, account, severity in incident_scenarios:
            assessment = self.blast_analyzer.assess_blast_radius(service, region, account, severity)
            assessments.append((assessment, severity))
        
        # Group by severity
        severity_groups = {}
        for assessment, severity in assessments:
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(assessment)
        
        # Property: Higher severity should have more containment recommendations
        severity_order = ['low', 'medium', 'high', 'critical']
        
        for i, severity in enumerate(severity_order):
            if severity not in severity_groups:
                continue
                
            avg_recommendations = sum(len(a.containment_recommendations) 
                                    for a in severity_groups[severity]) / len(severity_groups[severity])
            
            # Check against lower severities
            for j in range(i):
                lower_severity = severity_order[j]
                if lower_severity in severity_groups:
                    lower_avg = sum(len(a.containment_recommendations) 
                                  for a in severity_groups[lower_severity]) / len(severity_groups[lower_severity])
                    
                    # Allow some tolerance for randomness
                    assert avg_recommendations >= lower_avg - 1, \
                        f"{severity} incidents should have at least as many recommendations as {lower_severity}"
        
        # Property: Critical incidents should have comprehensive containment
        if 'critical' in severity_groups:
            for assessment in severity_groups['critical']:
                assert len(assessment.containment_recommendations) >= 5, \
                    "Critical incidents should have comprehensive containment recommendations"
                
                # Should mention executive/leadership notification
                containment_text = ' '.join(assessment.containment_recommendations).lower()
                assert any(word in containment_text for word in ['executive', 'leadership', 'legal']), \
                    "Critical incidents should include executive notification"


if __name__ == "__main__":
    # Run the property tests
    pytest.main([__file__, "-v", "--tb=short"])