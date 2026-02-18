"""
Property-Based Tests for Threat Prioritization and Response Quality

Feature: aws-bedrock-athena-ai, Property 5: Threat Prioritization and Response Quality
Validates: Requirements 2.2

These tests verify that higher business-impact threats receive higher priority scores 
and all threats include specific, actionable response guidance.
"""

import pytest
from hypothesis import given, strategies as st, settings, example, assume
from hypothesis.strategies import composite
from datetime import datetime
from unittest.mock import Mock, patch
import uuid

# Import the modules to test
from aws_bedrock_athena_ai.reasoning_engine.risk_assessor import RiskAssessor
from aws_bedrock_athena_ai.reasoning_engine.models import Threat, ThreatType, ThreatSeverity, Evidence


@composite
def threat_strategy(draw):
    """Generate realistic threat objects for testing"""
    threat_types = list(ThreatType)
    severities = list(ThreatSeverity)
    
    # Generate affected systems (more systems = higher business impact)
    num_systems = draw(st.integers(1, 20))
    affected_systems = [f"system-{i}" for i in range(num_systems)]
    
    # Generate threat with business impact indicators
    threat_type = draw(st.sampled_from(threat_types))
    severity = draw(st.sampled_from(severities))
    
    # Create description that may contain business impact keywords
    business_keywords = [
        'customer data', 'payment system', 'revenue', 'production',
        'critical service', 'compliance', 'regulatory', 'public'
    ]
    
    description_parts = [
        f"Security incident involving {threat_type.value}",
        draw(st.text(min_size=10, max_size=50))
    ]
    
    # Sometimes add business impact keywords
    if draw(st.booleans()):
        description_parts.append(draw(st.sampled_from(business_keywords)))
    
    description = " ".join(description_parts)
    
    return Threat(
        threat_id=str(uuid.uuid4()),
        threat_type=threat_type,
        severity=severity,
        title=f"{threat_type.value.title()} Threat",
        description=description,
        affected_systems=affected_systems,
        indicators=draw(st.lists(st.text(min_size=3, max_size=20), min_size=1, max_size=5)),
        timeline=[],
        evidence=[],
        confidence=draw(st.floats(0.1, 1.0)),
        first_seen=datetime.now(),
        last_seen=datetime.now()
    )


class TestThreatPrioritizationProperties:
    """Property-based tests for threat prioritization and response quality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.risk_assessor = RiskAssessor()
    
    @given(st.lists(threat_strategy(), min_size=2, max_size=10))
    @settings(max_examples=30, deadline=20000)
    def test_severity_based_prioritization(self, threats):
        """
        Property 5: Threat Prioritization - Severity-Based Ordering
        
        For any set of threats, higher severity threats should receive higher 
        priority scores than lower severity threats.
        """
        assume(len(threats) >= 2)  # Need at least 2 threats to compare
        
        # Prioritize threats
        prioritized_threats = self.risk_assessor.prioritize_threats(threats)
        
        # Property: Critical threats should come before high, high before medium, etc.
        severity_order = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.INFO: 0
        }
        
        # Check that threats are ordered by severity (with some flexibility for equal severities)
        for i in range(len(prioritized_threats) - 1):
            current_severity = severity_order[prioritized_threats[i].severity]
            next_severity = severity_order[prioritized_threats[i + 1].severity]
            
            # Current threat should have equal or higher severity than next
            assert current_severity >= next_severity, (
                f"Threat prioritization violated severity ordering: "
                f"{prioritized_threats[i].severity.value} should come before "
                f"{prioritized_threats[i + 1].severity.value}"
            )
    
    @given(st.lists(threat_strategy(), min_size=1, max_size=5))
    @settings(max_examples=25, deadline=15000)
    def test_business_impact_scoring_consistency(self, threats):
        """
        Property 5: Business Impact Scoring Consistency
        
        For any threat, business impact scores should be consistent with 
        threat characteristics and provide meaningful differentiation.
        """
        for threat in threats:
            business_impact = self.risk_assessor.calculate_business_impact_score(threat)
            
            # Property: Business impact score should be valid
            assert 0.0 <= business_impact['overall_score'] <= 10.0, (
                f"Invalid business impact score: {business_impact['overall_score']}"
            )
            
            # Property: Critical threats should have higher business impact
            if threat.severity == ThreatSeverity.CRITICAL:
                assert business_impact['overall_score'] >= 5.0, (
                    f"Critical threat has low business impact score: {business_impact['overall_score']}"
                )
            
            # Property: Data breach threats should have high compliance impact
            if threat.threat_type == ThreatType.DATA_BREACH:
                assert business_impact['compliance_impact'] in ['high', 'critical'], (
                    f"Data breach threat has low compliance impact: {business_impact['compliance_impact']}"
                )
            
            # Property: Threats affecting many systems should have higher operational impact
            if len(threat.affected_systems) > 10:
                assert business_impact['operational_impact'] in ['high', 'critical'], (
                    f"Wide-impact threat has low operational impact: {business_impact['operational_impact']}"
                )
    
    @given(st.lists(threat_strategy(), min_size=1, max_size=8))
    @settings(max_examples=20, deadline=15000)
    def test_actionable_response_guidance_completeness(self, threats):
        """
        Property 5: Response Guidance Completeness
        
        For any set of threats, the system should provide specific, actionable 
        response guidance with appropriate prioritization and resource allocation.
        """
        response_guidance = self.risk_assessor.generate_actionable_response_guidance(threats)
        
        # Property: Response guidance should be complete
        required_keys = [
            'immediate_actions', 'short_term_actions', 'long_term_actions',
            'resource_guidance', 'escalation_matrix', 'overall_priority'
        ]
        
        for key in required_keys:
            assert key in response_guidance, f"Missing required guidance key: {key}"
        
        # Property: Critical threats should generate immediate actions
        critical_threats = [t for t in threats if t.severity == ThreatSeverity.CRITICAL]
        if critical_threats:
            assert len(response_guidance['immediate_actions']) > 0, (
                "Critical threats present but no immediate actions generated"
            )
            assert response_guidance['overall_priority'] in ['critical', 'high'], (
                f"Critical threats present but overall priority is {response_guidance['overall_priority']}"
            )
        
        # Property: All action items should have required fields
        all_actions = (
            response_guidance['immediate_actions'] +
            response_guidance['short_term_actions'] +
            response_guidance['long_term_actions']
        )
        
        for action in all_actions:
            required_action_keys = ['action', 'timeline', 'owner', 'business_justification']
            for key in required_action_keys:
                assert key in action, f"Action missing required field: {key}"
                assert action[key], f"Action has empty {key} field"
    
    @given(threat_strategy(), threat_strategy())
    @settings(max_examples=20, deadline=10000)
    def test_priority_score_consistency(self, threat1, threat2):
        """
        Property 5: Priority Score Consistency
        
        For any two threats, the threat with higher business impact should 
        receive a higher priority score.
        """
        # Calculate priority scores
        priority1 = self.risk_assessor._calculate_threat_priority(threat1)
        priority2 = self.risk_assessor._calculate_threat_priority(threat2)
        
        # Property: Priority scores should be positive
        assert priority1 > 0, f"Invalid priority score for threat1: {priority1}"
        assert priority2 > 0, f"Invalid priority score for threat2: {priority2}"
        
        # Property: Higher severity should generally mean higher priority
        severity_order = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.INFO: 0
        }
        
        severity1 = severity_order[threat1.severity]
        severity2 = severity_order[threat2.severity]
        
        # If severities are significantly different, priority should reflect this
        if severity1 > severity2 + 1:  # Allow some flexibility
            assert priority1 > priority2, (
                f"Higher severity threat has lower priority: "
                f"{threat1.severity.value} (score: {priority1}) vs "
                f"{threat2.severity.value} (score: {priority2})"
            )
    
    @given(st.lists(threat_strategy(), min_size=3, max_size=6))
    @settings(max_examples=15, deadline=15000)
    def test_escalation_matrix_appropriateness(self, threats):
        """
        Property 5: Escalation Matrix Appropriateness
        
        For any set of threats, escalation procedures should be appropriate 
        for the threat severity and business impact.
        """
        response_guidance = self.risk_assessor.generate_actionable_response_guidance(threats)
        escalation_matrix = response_guidance['escalation_matrix']
        
        # Property: Escalation matrix should exist
        assert isinstance(escalation_matrix, dict), "Escalation matrix should be a dictionary"
        
        # Property: Critical threats should trigger immediate escalation
        critical_threats = [t for t in threats if t.severity == ThreatSeverity.CRITICAL]
        if critical_threats:
            assert 'immediate_escalation' in escalation_matrix, (
                "Critical threats present but no immediate escalation defined"
            )
            
            immediate_escalation = escalation_matrix['immediate_escalation']
            assert len(immediate_escalation) > 0, "Immediate escalation list is empty"
            
            # Should include senior leadership for critical threats
            escalation_text = ' '.join(immediate_escalation).lower()
            assert any(role in escalation_text for role in ['ciso', 'cto', 'ceo']), (
                "Critical threats should escalate to senior leadership"
            )
        
        # Property: Should always have regular reporting
        assert 'regular_reporting' in escalation_matrix, "Missing regular reporting escalation"
    
    def test_risk_assessment_integration(self):
        """
        Test integration between risk assessment and prioritization.
        This verifies that the components work together correctly.
        """
        # Create test threats with different characteristics
        critical_threat = Threat(
            threat_id=str(uuid.uuid4()),
            threat_type=ThreatType.DATA_BREACH,
            severity=ThreatSeverity.CRITICAL,
            title="Customer Data Breach",
            description="Unauthorized access to customer payment data",
            affected_systems=["payment-db", "web-app", "api-gateway"],
            indicators=["data_exfiltration", "unauthorized_access"],
            timeline=[],
            evidence=[],
            confidence=0.95
        )
        
        low_threat = Threat(
            threat_id=str(uuid.uuid4()),
            threat_type=ThreatType.CONFIGURATION_ISSUE,
            severity=ThreatSeverity.LOW,
            title="Minor Config Issue",
            description="Non-critical configuration drift detected",
            affected_systems=["test-server"],
            indicators=["config_drift"],
            timeline=[],
            evidence=[],
            confidence=0.6
        )
        
        threats = [critical_threat, low_threat]
        
        # Test risk assessment
        risk_assessment = self.risk_assessor.assess_risk_levels(threats)
        
        # Verify risk assessment properties
        assert risk_assessment.overall_risk_score > 5.0, "Should have high risk with critical threat"
        assert risk_assessment.critical_threats == 1, "Should count one critical threat"
        assert risk_assessment.low_threats == 1, "Should count one low threat"
        
        # Test prioritization
        prioritized = self.risk_assessor.prioritize_threats(threats)
        
        # Critical threat should come first
        assert prioritized[0].severity == ThreatSeverity.CRITICAL, "Critical threat should be prioritized first"
        assert prioritized[1].severity == ThreatSeverity.LOW, "Low threat should be prioritized last"


# Run the tests
if __name__ == '__main__':
    pytest.main([__file__, '-v'])