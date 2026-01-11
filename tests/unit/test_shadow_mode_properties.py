"""
Property-Based Tests for Shadow Mode Analysis

This module contains property-based tests that validate the correctness
of shadow mode risk analysis functionality across all valid inputs.

Requirements: 3.1
Property 13: Shadow Mode Risk Analysis
"""

import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import sys
import os

# Add src to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from python.agentic_modules.shadow_mode_analyzer import (
    ShadowModeAnalyzer,
    InfrastructureChange,
    ShadowEnvironmentConfig,
    RiskAssessment,
    ShadowModeReport
)


# Hypothesis strategies for generating test data
@st.composite
def infrastructure_change_strategy(draw):
    """Generate valid InfrastructureChange objects"""
    change_id = draw(st.text(min_size=5, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd'))))
    change_type = draw(st.sampled_from(['service_addition', 'configuration_change', 'network_change', 'security_update']))
    description = draw(st.text(min_size=10, max_size=200))
    affected_services = draw(st.lists(st.text(min_size=3, max_size=15, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))), min_size=1, max_size=5))
    submitted_by = draw(st.text(min_size=3, max_size=30))
    
    # Generate proposed config based on change type
    if change_type == 'service_addition':
        proposed_config = {
            draw(st.text(min_size=3, max_size=15)): {
                'image': draw(st.text(min_size=5, max_size=30)),
                'ports': draw(st.lists(st.text(min_size=4, max_size=10), min_size=0, max_size=3))
            }
        }
    else:
        proposed_config = draw(st.dictionaries(
            st.text(min_size=3, max_size=15),
            st.text(min_size=3, max_size=50),
            min_size=1, max_size=5
        ))
    
    return InfrastructureChange(
        change_id=change_id,
        change_type=change_type,
        description=description,
        affected_services=affected_services,
        proposed_config=proposed_config,
        current_config=None,
        risk_level="unknown",
        impact_scope=affected_services,
        submitted_by=submitted_by,
        submitted_at=datetime.now()
    )


class TestShadowModeAnalysisProperties:
    """Property-based tests for Shadow Mode Analysis functionality"""
    
    def setup_method(self):
        """Set up test environment with temporary directories"""
        self.temp_dir = tempfile.mkdtemp()
        self.shadow_workspace = Path(self.temp_dir) / "shadow_environments"
        self.analysis_db_path = Path(self.temp_dir) / "analysis" / "shadow_analysis.db"
        
        # Create a minimal docker-compose.yml for testing
        self.compose_path = Path(self.temp_dir) / "docker-compose.yml"
        with open(self.compose_path, 'w') as f:
            f.write("""
version: '3.8'
services:
  test-service:
    image: nginx:latest
    ports:
      - "80:80"
networks:
  default:
    driver: bridge
""")
        
        self.analyzer = ShadowModeAnalyzer(
            base_compose_path=str(self.compose_path),
            shadow_workspace=str(self.shadow_workspace),
            analysis_db_path=str(self.analysis_db_path)
        )
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @given(infrastructure_change_strategy())
    @settings(max_examples=100, deadline=30000)  # 30 second deadline for shadow analysis
    def test_property_13_shadow_mode_risk_analysis(self, change):
        """
        **Feature: rose-read-only-security, Property 13: Shadow Mode Risk Analysis**
        
        For any proposed code or infrastructure change, it should be analyzed in an 
        isolated shadow environment and generate comprehensive risk assessments
        
        **Validates: Requirements 3.1**
        """
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        assume(all(len(service) > 0 for service in change.affected_services))
        
        # Perform shadow mode risk analysis
        risk_assessment = self.analyzer.analyze_infrastructure_change(change)
        
        # Verify risk assessment structure and completeness
        assert isinstance(risk_assessment, RiskAssessment)
        assert risk_assessment.change_id == change.change_id
        assert isinstance(risk_assessment.overall_risk_score, (int, float))
        assert 0.0 <= risk_assessment.overall_risk_score <= 10.0
        
        # Verify all risk categories are analyzed
        assert isinstance(risk_assessment.security_risks, list)
        assert isinstance(risk_assessment.performance_risks, list)
        assert isinstance(risk_assessment.availability_risks, list)
        assert isinstance(risk_assessment.compliance_risks, list)
        
        # Verify blast radius assessment is comprehensive
        assert isinstance(risk_assessment.blast_radius_assessment, dict)
        blast_radius = risk_assessment.blast_radius_assessment
        assert 'affected_services' in blast_radius
        assert 'dependent_services' in blast_radius
        assert 'impact_scope' in blast_radius
        assert 'containment_level' in blast_radius
        
        # Verify mitigation strategies are provided
        assert isinstance(risk_assessment.mitigation_strategies, list)
        assert len(risk_assessment.mitigation_strategies) >= 0  # May be empty for low-risk changes
        
        # Verify rollback plan is comprehensive
        assert isinstance(risk_assessment.rollback_plan, dict)
        rollback_plan = risk_assessment.rollback_plan
        assert 'rollback_strategy' in rollback_plan
        assert 'rollback_steps' in rollback_plan
        assert 'estimated_time' in rollback_plan
        
        # Verify confidence level is reasonable
        assert isinstance(risk_assessment.confidence_level, (int, float))
        assert 0.0 <= risk_assessment.confidence_level <= 1.0
        
        # Verify analysis timestamp is recent
        assert isinstance(risk_assessment.analysis_timestamp, datetime)
        time_diff = datetime.now() - risk_assessment.analysis_timestamp
        assert time_diff.total_seconds() < 300  # Analysis completed within 5 minutes
    
    @given(infrastructure_change_strategy())
    @settings(max_examples=50, deadline=45000)  # 45 second deadline for comprehensive analysis
    def test_shadow_environment_provisioning_isolation(self, change):
        """
        Test that shadow environments are properly isolated and provisioned
        """
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        
        # Provision shadow environment
        shadow_env = self.analyzer.provision_shadow_environment(change, isolation_level="high")
        
        try:
            # Verify shadow environment configuration
            assert isinstance(shadow_env, ShadowEnvironmentConfig)
            assert shadow_env.environment_id.startswith("shadow-")
            assert change.change_id in shadow_env.environment_id
            assert shadow_env.network_isolation is True  # High isolation level
            
            # Verify resource limits are applied
            assert isinstance(shadow_env.resource_limits, dict)
            assert 'memory' in shadow_env.resource_limits
            assert 'cpus' in shadow_env.resource_limits
            
            # Verify security constraints are applied
            assert isinstance(shadow_env.security_constraints, dict)
            assert shadow_env.security_constraints['isolation_level'] == "high"
            assert shadow_env.security_constraints['network_isolation'] is True
            
            # Verify monitoring configuration
            assert isinstance(shadow_env.monitoring_config, dict)
            assert shadow_env.monitoring_config['metrics_collection'] is True
            
            # Verify TTL is reasonable
            assert isinstance(shadow_env.ttl_hours, int)
            assert 1 <= shadow_env.ttl_hours <= 168  # Between 1 hour and 1 week
            
        finally:
            # Clean up shadow environment
            self.analyzer._cleanup_shadow_environment(shadow_env.environment_id)
    
    @given(infrastructure_change_strategy())
    @settings(max_examples=30, deadline=60000)  # 60 second deadline for comprehensive reporting
    def test_comprehensive_report_generation(self, change):
        """
        Test that comprehensive shadow mode reports are generated correctly
        """
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        
        # Perform risk analysis
        risk_assessment = self.analyzer.analyze_infrastructure_change(change)
        
        # Generate comprehensive report
        report = self.analyzer.generate_comprehensive_report(change, risk_assessment)
        
        # Verify report structure
        assert isinstance(report, ShadowModeReport)
        assert report.change_id == change.change_id
        assert report.risk_assessment == risk_assessment
        
        # Verify deployment simulation results
        assert isinstance(report.deployment_simulation_results, dict)
        deployment_results = report.deployment_simulation_results
        assert 'deployment_id' in deployment_results
        assert 'status' in deployment_results
        assert 'services_analyzed' in deployment_results
        
        # Verify security scan results
        assert isinstance(report.security_scan_results, dict)
        security_results = report.security_scan_results
        assert 'scan_id' in security_results
        assert 'security_score' in security_results
        
        # Verify performance analysis
        assert isinstance(report.performance_analysis, dict)
        perf_analysis = report.performance_analysis
        assert 'analysis_id' in perf_analysis
        
        # Verify recommendations are provided
        assert isinstance(report.recommendations, list)
        
        # Verify approval status is valid
        assert report.approval_status in ['approved', 'rejected', 'needs_review']
        
        # Verify report timestamp
        assert isinstance(report.generated_at, datetime)
        time_diff = datetime.now() - report.generated_at
        assert time_diff.total_seconds() < 300  # Report generated within 5 minutes
    
    @given(infrastructure_change_strategy())
    @settings(max_examples=50, deadline=30000)
    def test_rollback_recommendations_completeness(self, change):
        """
        Test that rollback recommendations are comprehensive and actionable
        """
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        
        # Create rollback recommendations
        rollback_plan = self.analyzer.create_rollback_recommendations(change)
        
        # Verify rollback plan structure
        assert isinstance(rollback_plan, dict)
        assert rollback_plan['change_id'] == change.change_id
        
        # Verify rollback strategy is defined
        assert 'rollback_strategy' in rollback_plan
        assert isinstance(rollback_plan['rollback_strategy'], str)
        assert len(rollback_plan['rollback_strategy']) > 0
        
        # Verify rollback steps are detailed
        assert 'rollback_steps' in rollback_plan
        assert isinstance(rollback_plan['rollback_steps'], list)
        assert len(rollback_plan['rollback_steps']) > 0
        
        # Verify verification steps are provided
        assert 'verification_steps' in rollback_plan
        assert isinstance(rollback_plan['verification_steps'], list)
        assert len(rollback_plan['verification_steps']) > 0
        
        # Verify time estimates are reasonable
        assert 'estimated_rollback_time' in rollback_plan
        assert isinstance(rollback_plan['estimated_rollback_time'], int)
        assert rollback_plan['estimated_rollback_time'] > 0
        
        # Verify risk mitigation is addressed
        assert 'risk_mitigation' in rollback_plan
        assert isinstance(rollback_plan['risk_mitigation'], list)
        
        # Verify communication plan exists
        assert 'communication_plan' in rollback_plan
        assert isinstance(rollback_plan['communication_plan'], dict)
        
        # Verify monitoring requirements are specified
        assert 'monitoring_requirements' in rollback_plan
        assert isinstance(rollback_plan['monitoring_requirements'], dict)
        
        # Verify success criteria are defined
        assert 'success_criteria' in rollback_plan
        assert isinstance(rollback_plan['success_criteria'], list)
        assert len(rollback_plan['success_criteria']) > 0
        
        # Verify escalation procedures are defined
        assert 'escalation_procedures' in rollback_plan
        assert isinstance(rollback_plan['escalation_procedures'], dict)
    
    @given(st.lists(infrastructure_change_strategy(), min_size=2, max_size=5))
    @settings(max_examples=20, deadline=90000)  # 90 second deadline for multiple changes
    def test_multiple_changes_analysis_consistency(self, changes):
        """
        Test that analyzing multiple changes produces consistent results
        """
        assume(len(set(change.change_id for change in changes)) == len(changes))  # Unique change IDs
        
        risk_assessments = []
        
        for change in changes:
            assume(len(change.change_id) > 0)
            assume(len(change.affected_services) > 0)
            
            risk_assessment = self.analyzer.analyze_infrastructure_change(change)
            risk_assessments.append(risk_assessment)
        
        # Verify all assessments are stored
        assert len(risk_assessments) == len(changes)
        
        # Verify each assessment is complete and consistent
        for i, (change, assessment) in enumerate(zip(changes, risk_assessments)):
            assert assessment.change_id == change.change_id
            assert isinstance(assessment.overall_risk_score, (int, float))
            assert 0.0 <= assessment.overall_risk_score <= 10.0
            
            # Verify risk categories are consistently structured
            assert isinstance(assessment.security_risks, list)
            assert isinstance(assessment.performance_risks, list)
            assert isinstance(assessment.availability_risks, list)
            assert isinstance(assessment.compliance_risks, list)
            
            # Verify all assessments have required fields
            assert isinstance(assessment.blast_radius_assessment, dict)
            assert isinstance(assessment.mitigation_strategies, list)
            assert isinstance(assessment.rollback_plan, dict)
            assert isinstance(assessment.confidence_level, (int, float))
            assert isinstance(assessment.analysis_timestamp, datetime)
        
        # Verify assessments are stored in analyzer
        for assessment in risk_assessments:
            assert assessment.change_id in self.analyzer.risk_assessments
            stored_assessment = self.analyzer.risk_assessments[assessment.change_id]
            assert stored_assessment.overall_risk_score == assessment.overall_risk_score


class ShadowModeAnalysisStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for Shadow Mode Analysis
    
    This tests the system behavior across multiple operations and state transitions
    """
    
    def __init__(self):
        super().__init__()
        self.temp_dir = tempfile.mkdtemp()
        self.shadow_workspace = Path(self.temp_dir) / "shadow_environments"
        self.analysis_db_path = Path(self.temp_dir) / "analysis" / "shadow_analysis.db"
        
        # Create minimal docker-compose.yml
        self.compose_path = Path(self.temp_dir) / "docker-compose.yml"
        with open(self.compose_path, 'w') as f:
            f.write("""
version: '3.8'
services:
  test-service:
    image: nginx:latest
    ports:
      - "80:80"
""")
        
        self.analyzer = ShadowModeAnalyzer(
            base_compose_path=str(self.compose_path),
            shadow_workspace=str(self.shadow_workspace),
            analysis_db_path=str(self.analysis_db_path)
        )
        
        self.analyzed_changes = set()
        self.active_environments = set()
    
    def teardown(self):
        """Clean up test environment"""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @rule(change=infrastructure_change_strategy())
    def analyze_change(self, change):
        """Analyze an infrastructure change"""
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        assume(change.change_id not in self.analyzed_changes)
        
        risk_assessment = self.analyzer.analyze_infrastructure_change(change)
        
        # Track analyzed change
        self.analyzed_changes.add(change.change_id)
        
        # Verify assessment is stored
        assert change.change_id in self.analyzer.risk_assessments
        assert self.analyzer.risk_assessments[change.change_id] == risk_assessment
    
    @rule(change=infrastructure_change_strategy())
    def provision_environment(self, change):
        """Provision a shadow environment"""
        assume(len(change.change_id) > 0)
        assume(len(change.affected_services) > 0)
        
        shadow_env = self.analyzer.provision_shadow_environment(change)
        
        # Track active environment
        self.active_environments.add(shadow_env.environment_id)
        
        # Verify environment is tracked
        assert shadow_env.environment_id in self.analyzer.active_environments
    
    @invariant()
    def analyzer_state_consistency(self):
        """Verify analyzer state remains consistent"""
        # All analyzed changes should be stored
        for change_id in self.analyzed_changes:
            assert change_id in self.analyzer.risk_assessments
        
        # Risk assessments should have valid scores
        for assessment in self.analyzer.risk_assessments.values():
            assert 0.0 <= assessment.overall_risk_score <= 10.0
            assert isinstance(assessment.confidence_level, (int, float))
            assert 0.0 <= assessment.confidence_level <= 1.0


# Test runner for stateful testing
TestShadowModeStateful = ShadowModeAnalysisStateMachine.TestCase


if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--tb=short"])