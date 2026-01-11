"""
Property-Based Tests for Technology Stack Compliance Analysis

This module implements property-based tests to validate the correctness
of technology stack compliance analysis, focusing on free-tier resource
usage and deployment self-sufficiency properties.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import sys
import os
from hypothesis import given, strategies as st, settings, assume
import json

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from src.python.use_case_demo.technology_stack_analyzer import (
    TechnologyStackAnalyzer, TechnologyComponent, ComplianceResult, DeploymentReadiness
)


class TestTechnologyComplianceProperties(unittest.TestCase):
    """Property-based tests for technology stack compliance analysis."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = TechnologyStackAnalyzer(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_component(self, name="TestComponent", cost_tier="FREE", 
                            security_rating="HIGH", deployment_complexity="SIMPLE",
                            dependencies=None, vulnerabilities=None):
        """Create a test technology component."""
        if dependencies is None:
            dependencies = []
        if vulnerabilities is None:
            vulnerabilities = []
            
        return TechnologyComponent(
            name=name,
            version="1.0.0",
            category="database",
            license="MIT",
            security_rating=security_rating,
            cost_tier=cost_tier,
            deployment_complexity=deployment_complexity,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            alternatives=["Alternative1", "Alternative2"]
        )
    
    @given(st.lists(
        st.builds(
            TechnologyComponent,
            name=st.text(min_size=1, max_size=15, alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            version=st.sampled_from(['latest', '1.0.0', '2.1.3']),
            category=st.sampled_from(['database', 'ai_framework', 'security_tool']),
            license=st.sampled_from(['MIT', 'Apache-2.0', 'GPL-2.0']),
            security_rating=st.sampled_from(['HIGH', 'MEDIUM', 'LOW']),
            cost_tier=st.sampled_from(['FREE', 'PAID', 'ENTERPRISE']),
            deployment_complexity=st.sampled_from(['SIMPLE', 'MODERATE', 'COMPLEX']),
            dependencies=st.lists(st.text(min_size=1, max_size=8, alphabet="abcdefghijklmnopqrstuvwxyz"), max_size=3),
            vulnerabilities=st.lists(st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"), max_size=3),
            alternatives=st.lists(st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"), min_size=1, max_size=3)
        ),
        min_size=1, max_size=5
    ))
    @settings(max_examples=50, deadline=None)
    def test_property_26_free_tier_resource_usage(self, components):
        """
        Property 26: Free-Tier Resource Usage
        For any system deployment, all services should operate within AWS free-tier 
        limits or use open-source alternatives exclusively.
        
        **Validates: Requirements 8.1**
        """
        # Create analyzer with test components
        analyzer = TechnologyStackAnalyzer(self.temp_dir)
        
        # Replace stack components with test components
        test_stack = {}
        for i, component in enumerate(components):
            test_stack[f"component_{i}"] = component
        
        analyzer.stack_components = test_stack
        
        # Perform analysis
        analysis = analyzer.analyze_technology_stack()
        
        # Verify analysis completed successfully
        self.assertNotIn('error', analysis)
        self.assertIn('cost_analysis', analysis)
        
        cost_analysis = analysis['cost_analysis']
        
        # Property: Free-tier compliance should be deterministic based on component cost tiers
        free_tier_components = sum(1 for comp in components if comp.cost_tier == 'FREE')
        total_components = len(components)
        expected_free_tier_percentage = (free_tier_components / total_components) * 100
        
        self.assertAlmostEqual(
            cost_analysis['free_tier_percentage'], 
            expected_free_tier_percentage, 
            places=1,
            msg="Free-tier percentage calculation should be accurate"
        )
        
        # Property: Total cost should be sum of individual component costs
        expected_total_cost = 0.0
        for component in components:
            if component.cost_tier == 'PAID':
                expected_total_cost += 100.0  # Base paid cost
            elif component.cost_tier == 'ENTERPRISE':
                expected_total_cost += 500.0  # Base enterprise cost
            
            # Add complexity costs
            if component.deployment_complexity == 'COMPLEX':
                expected_total_cost += 50.0
            
            # Add dependency costs
            expected_total_cost += len(component.dependencies) * 10.0
        
        self.assertAlmostEqual(
            cost_analysis['total_estimated_monthly_cost'],
            expected_total_cost,
            places=2,
            msg="Total cost should equal sum of component costs"
        )
        
        # Property: Free-tier compliance should be true only when total cost is zero
        if all(comp.cost_tier == 'FREE' and comp.deployment_complexity != 'COMPLEX' 
               and len(comp.dependencies) == 0 for comp in components):
            self.assertTrue(
                cost_analysis['free_tier_compliant'],
                msg="Should be free-tier compliant when all components are free with no overhead"
            )
        
        # Property: Cost optimization should be needed when cost exceeds threshold
        if cost_analysis['total_estimated_monthly_cost'] > analyzer.cost_thresholds['optimization_threshold']:
            self.assertTrue(
                cost_analysis['cost_optimization_needed'],
                msg="Cost optimization should be flagged when threshold exceeded"
            )
    
    @given(st.lists(
        st.builds(
            TechnologyComponent,
            name=st.text(min_size=1, max_size=15, alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            version=st.sampled_from(['latest', '1.0.0', '2.1.3']),
            category=st.sampled_from(['database', 'ai_framework', 'security_tool']),
            license=st.sampled_from(['MIT', 'Apache-2.0', 'GPL-2.0']),
            security_rating=st.sampled_from(['HIGH', 'MEDIUM', 'LOW']),
            cost_tier=st.sampled_from(['FREE', 'PAID', 'ENTERPRISE']),
            deployment_complexity=st.sampled_from(['SIMPLE', 'MODERATE', 'COMPLEX']),
            dependencies=st.lists(st.text(min_size=1, max_size=8, alphabet="abcdefghijklmnopqrstuvwxyz"), max_size=3),
            vulnerabilities=st.lists(st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"), max_size=3),
            alternatives=st.lists(st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"), min_size=1, max_size=3)
        ),
        min_size=1, max_size=5
    ))
    @settings(max_examples=50, deadline=None)
    def test_property_27_deployment_self_sufficiency(self, components):
        """
        Property 27: Deployment Self-Sufficiency
        For any system deployment, it should complete successfully using only 
        AWS credentials and automatically install all dependencies.
        
        **Validates: Requirements 8.4, 8.5**
        """
        # Create analyzer with test components
        analyzer = TechnologyStackAnalyzer(self.temp_dir)
        
        # Replace stack components with test components
        test_stack = {}
        for i, component in enumerate(components):
            test_stack[f"component_{i}"] = component
        
        analyzer.stack_components = test_stack
        
        # Perform analysis
        analysis = analyzer.analyze_technology_stack()
        
        # Verify analysis completed successfully
        self.assertNotIn('error', analysis)
        self.assertIn('deployment_readiness', analysis)
        
        deployment_readiness = analysis['deployment_readiness']
        
        # Property: Deployment readiness should be inversely related to complexity
        complex_components = sum(1 for comp in components if comp.deployment_complexity == 'COMPLEX')
        total_components = len(components)
        
        if complex_components == 0:
            # No complex components should result in higher readiness
            self.assertGreaterEqual(
                deployment_readiness['overall_score'],
                60.0,
                msg="Deployment readiness should be higher with no complex components"
            )
        
        # Property: Blockers should exist when components are non-compliant
        non_compliant_count = 0
        for component in components:
            # Count non-compliant components based on our compliance rules
            if (component.security_rating == 'LOW' or 
                component.license in ['SSPL', 'Commons Clause'] or
                component.cost_tier != 'FREE' or
                len(component.vulnerabilities) > 5):
                non_compliant_count += 1
        
        if non_compliant_count > 0:
            self.assertGreater(
                len(deployment_readiness['blockers']),
                0,
                msg="Should have blockers when components are non-compliant"
            )
        
        # Property: Readiness level should be consistent with overall score
        overall_score = deployment_readiness['overall_score']
        readiness_level = deployment_readiness['readiness_level']
        
        if overall_score >= 80 and len(deployment_readiness['blockers']) == 0:
            self.assertEqual(readiness_level, "READY")
        elif overall_score >= 60:
            self.assertEqual(readiness_level, "NEEDS_ATTENTION")
        else:
            self.assertEqual(readiness_level, "NOT_READY")
        
        # Property: Security score should reflect component security ratings
        high_security_components = sum(1 for comp in components if comp.security_rating == 'HIGH')
        low_security_components = sum(1 for comp in components if comp.security_rating == 'LOW')
        
        if high_security_components > low_security_components:
            self.assertGreaterEqual(
                deployment_readiness['security_score'],
                70.0,
                msg="Security score should be higher when more components have high security rating"
            )
        
        # Property: Performance score should reflect deployment complexity
        simple_components = sum(1 for comp in components if comp.deployment_complexity == 'SIMPLE')
        
        if simple_components == total_components:
            self.assertGreaterEqual(
                deployment_readiness['performance_score'],
                90.0,
                msg="Performance score should be high when all components are simple to deploy"
            )
    
    def test_compliance_rules_validation(self):
        """Test that compliance rules are properly applied."""
        analyzer = TechnologyStackAnalyzer(self.temp_dir)
        
        # Test component with forbidden license
        forbidden_component = self.create_test_component(
            name="ForbiddenComponent",
            cost_tier="FREE"
        )
        forbidden_component.license = "SSPL"  # Forbidden license
        
        compliance = analyzer._check_component_compliance(forbidden_component)
        self.assertFalse(compliance.compliant, "Component with forbidden license should not be compliant")
        self.assertTrue(any("License SSPL is not permitted" in issue for issue in compliance.issues))
        
        # Test component with too many vulnerabilities
        vulnerable_component = self.create_test_component(
            name="VulnerableComponent",
            vulnerabilities=["vuln1", "vuln2", "vuln3", "vuln4", "vuln5", "vuln6"]  # 6 vulnerabilities > 5 limit
        )
        
        compliance = analyzer._check_component_compliance(vulnerable_component)
        self.assertFalse(compliance.compliant, "Component with too many vulnerabilities should not be compliant")
        self.assertTrue(any("vulnerabilities" in issue for issue in compliance.issues))
    
    def test_cost_calculation_accuracy(self):
        """Test that cost calculations are accurate."""
        analyzer = TechnologyStackAnalyzer(self.temp_dir)
        
        # Test free component
        free_component = self.create_test_component(
            name="FreeComponent",
            cost_tier="FREE",
            deployment_complexity="SIMPLE",
            dependencies=[]
        )
        
        cost_assessment = analyzer._assess_component_cost(free_component)
        self.assertEqual(cost_assessment['estimated_monthly_cost'], 0.0)
        self.assertTrue(cost_assessment['free_tier_compliant'])
        
        # Test paid component with complex deployment
        paid_component = self.create_test_component(
            name="PaidComponent",
            cost_tier="PAID",
            deployment_complexity="COMPLEX",
            dependencies=["dep1", "dep2"]
        )
        
        cost_assessment = analyzer._assess_component_cost(paid_component)
        expected_cost = 100.0 + 50.0 + (2 * 10.0)  # paid + complex + dependencies
        self.assertEqual(cost_assessment['estimated_monthly_cost'], expected_cost)
        self.assertFalse(cost_assessment['free_tier_compliant'])
    
    def test_component_analysis_consistency(self):
        """Test that individual component analysis is consistent and deterministic."""
        analyzer = TechnologyStackAnalyzer(self.temp_dir)
        
        component = self.create_test_component(
            name="ConsistentComponent",
            cost_tier="FREE",
            security_rating="HIGH",
            deployment_complexity="SIMPLE"
        )
        
        # Analyze the same component multiple times
        analysis1 = analyzer._analyze_component(component)
        analysis2 = analyzer._analyze_component(component)
        
        # Results should be identical
        self.assertEqual(
            analysis1['security_assessment']['security_score'],
            analysis2['security_assessment']['security_score'],
            msg="Security assessment should be deterministic"
        )
        
        self.assertEqual(
            analysis1['cost_assessment']['estimated_monthly_cost'],
            analysis2['cost_assessment']['estimated_monthly_cost'],
            msg="Cost assessment should be deterministic"
        )
        
        self.assertEqual(
            analysis1['deployment_assessment']['deployment_score'],
            analysis2['deployment_assessment']['deployment_score'],
            msg="Deployment assessment should be deterministic"
        )
        
        # Compliance status should be consistent
        compliance1 = analysis1['compliance_status']
        compliance2 = analysis2['compliance_status']
        
        self.assertEqual(compliance1.compliant, compliance2.compliant)
        self.assertEqual(compliance1.risk_score, compliance2.risk_score)
        self.assertEqual(compliance1.cost_impact, compliance2.cost_impact)


if __name__ == '__main__':
    unittest.main()