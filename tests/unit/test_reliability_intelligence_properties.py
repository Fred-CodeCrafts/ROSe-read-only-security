"""
Property-Based Tests for Reliability Intelligence and Incident Analysis

This module contains property-based tests that validate the correctness
of reliability intelligence, automated RCA, and performance analysis functionality.

Requirements: 3.2, 3.3, 3.4, 3.5
Property 14: Reliability Intelligence Analysis
Property 15: Automated Incident Analysis
Property 16: Performance Pattern Analysis
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
import statistics
import random

# Add src to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from python.agentic_modules.reliability_intelligence import (
    ReliabilityIntelligenceAnalyzer,
    SystemMetric,
    SystemMetricType,
    IncidentEvent,
    IncidentSeverity,
    ReliabilityPattern,
    RCAHypothesis,
    PerformanceAnalysis
)


# Hypothesis strategies for generating test data
@st.composite
def system_metric_strategy(draw):
    """Generate valid SystemMetric objects"""
    metric_type = draw(st.sampled_from(list(SystemMetricType)))
    
    # Generate realistic values based on metric type
    if metric_type in [SystemMetricType.CPU_UTILIZATION, SystemMetricType.MEMORY_UTILIZATION, SystemMetricType.DISK_UTILIZATION]:
        value = draw(st.floats(min_value=0.0, max_value=100.0))
    elif metric_type == SystemMetricType.ERROR_RATE:
        value = draw(st.floats(min_value=0.0, max_value=50.0))
    elif metric_type == SystemMetricType.RESPONSE_TIME:
        value = draw(st.floats(min_value=1.0, max_value=5000.0))
    elif metric_type == SystemMetricType.AVAILABILITY:
        value = draw(st.floats(min_value=90.0, max_value=100.0))
    else:
        value = draw(st.floats(min_value=0.0, max_value=10000.0))
    
    # Use fixed datetime range to avoid flaky strategy
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    timestamp = draw(st.datetimes(
        min_value=base_time,
        max_value=base_time + timedelta(days=7)
    ))
    
    service_name = draw(st.text(min_size=3, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))
    
    tags = draw(st.dictionaries(
        st.text(min_size=1, max_size=10),
        st.text(min_size=1, max_size=20),
        min_size=0, max_size=3
    ))
    
    unit = draw(st.sampled_from(['%', 'ms', 'MB', 'GB', 'req/s', 'count']))
    
    return SystemMetric(
        metric_type=metric_type,
        value=value,
        timestamp=timestamp,
        service_name=service_name,
        tags=tags,
        unit=unit
    )


@st.composite
def incident_event_strategy(draw):
    """Generate valid IncidentEvent objects"""
    incident_id = draw(st.text(min_size=5, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pd'))))
    title = draw(st.text(min_size=10, max_size=100))
    description = draw(st.text(min_size=20, max_size=500))
    severity = draw(st.sampled_from(list(IncidentSeverity)))
    affected_services = draw(st.lists(st.text(min_size=3, max_size=15), min_size=1, max_size=5))
    
    # Use fixed datetime range to avoid flaky strategy
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    start_time = draw(st.datetimes(
        min_value=base_time,
        max_value=base_time + timedelta(days=1)
    ))
    
    # End time might be None (ongoing incident) or after start time
    end_time = draw(st.one_of(
        st.none(),
        st.datetimes(
            min_value=start_time + timedelta(minutes=5),
            max_value=start_time + timedelta(hours=12)
        )
    ))
    
    status = draw(st.sampled_from(['open', 'investigating', 'resolved', 'closed']))
    
    tags = draw(st.dictionaries(
        st.text(min_size=1, max_size=10),
        st.text(min_size=1, max_size=20),
        min_size=0, max_size=3
    ))
    
    # Generate metrics during incident
    metrics_during_incident = draw(st.lists(system_metric_strategy(), min_size=0, max_size=10))
    
    # Generate timeline events
    timeline_events = draw(st.lists(
        st.dictionaries(
            st.text(min_size=1, max_size=15),
            st.one_of(st.text(min_size=1, max_size=50), st.datetimes()),
            min_size=1, max_size=5
        ),
        min_size=0, max_size=5
    ))
    
    return IncidentEvent(
        incident_id=incident_id,
        title=title,
        description=description,
        severity=severity,
        affected_services=affected_services,
        start_time=start_time,
        end_time=end_time,
        status=status,
        tags=tags,
        metrics_during_incident=metrics_during_incident,
        timeline_events=timeline_events
    )


class TestReliabilityIntelligenceProperties:
    """Property-based tests for Reliability Intelligence functionality"""
    
    def setup_method(self):
        """Set up test environment with temporary directories"""
        self.temp_dir = tempfile.mkdtemp()
        self.metrics_storage_path = Path(self.temp_dir) / "metrics"
        self.incidents_storage_path = Path(self.temp_dir) / "incidents"
        self.analysis_db_path = Path(self.temp_dir) / "analysis" / "reliability_analysis.db"
        
        self.analyzer = ReliabilityIntelligenceAnalyzer(
            metrics_storage_path=str(self.metrics_storage_path),
            incidents_storage_path=str(self.incidents_storage_path),
            analysis_db_path=str(self.analysis_db_path)
        )
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @given(st.lists(system_metric_strategy(), min_size=10, max_size=100))
    @settings(max_examples=50, deadline=30000)  # 30 second deadline
    def test_property_14_reliability_intelligence_analysis(self, metrics):
        """
        **Feature: ai-cybersecurity-platform, Property 14: Reliability Intelligence Analysis**
        
        For any system metrics indicating issues, appropriate analysis should be performed 
        and reliability intelligence reports should be generated with recommended actions
        
        **Validates: Requirements 3.2**
        """
        assume(len(metrics) >= 10)
        assume(len(set(m.service_name for m in metrics)) >= 1)  # At least one service
        
        # Perform reliability pattern analysis
        patterns = self.analyzer.analyze_reliability_patterns(metrics)
        
        # Verify patterns are properly structured
        assert isinstance(patterns, list)
        
        for pattern in patterns:
            assert isinstance(pattern, ReliabilityPattern)
            assert len(pattern.pattern_id) > 0
            assert pattern.pattern_type in ['degradation', 'spike', 'oscillation', 'trend']
            assert len(pattern.description) > 0
            assert isinstance(pattern.affected_metrics, list)
            assert len(pattern.affected_metrics) > 0
            assert isinstance(pattern.confidence_score, (int, float))
            assert 0.0 <= pattern.confidence_score <= 1.0
            assert pattern.frequency in ['daily', 'weekly', 'monthly', 'irregular', 'regular', 'continuous']
            assert isinstance(pattern.impact_assessment, dict)
            assert isinstance(pattern.predictive_indicators, list)
            assert isinstance(pattern.discovered_at, datetime)
        
        # Verify patterns are stored in analyzer
        for pattern in patterns:
            assert pattern.pattern_id in self.analyzer.reliability_patterns
            stored_pattern = self.analyzer.reliability_patterns[pattern.pattern_id]
            assert stored_pattern.confidence_score == pattern.confidence_score
            assert stored_pattern.pattern_type == pattern.pattern_type
        
        # Verify impact assessment contains required fields
        for pattern in patterns:
            impact = pattern.impact_assessment
            assert 'severity' in impact or 'affected_service' in impact
            if 'severity' in impact:
                assert impact['severity'] in ['low', 'medium', 'high', 'critical']
    
    @given(incident_event_strategy())
    @settings(max_examples=30, deadline=45000)  # 45 second deadline for incident analysis
    def test_property_15_automated_incident_analysis(self, incident):
        """
        **Feature: ai-cybersecurity-platform, Property 15: Automated Incident Analysis**
        
        For any simulated or real incident, the system should perform root cause analysis 
        and generate comprehensive hypothesis reports with recommended response procedures
        
        **Validates: Requirements 3.3, 3.5**
        """
        assume(len(incident.incident_id) > 0)
        assume(len(incident.affected_services) > 0)
        assume(all(len(service) > 0 for service in incident.affected_services))
        
        # Generate RCA hypotheses
        hypotheses = self.analyzer.generate_rca_hypotheses(incident)
        
        # Verify hypotheses structure
        assert isinstance(hypotheses, list)
        
        for hypothesis in hypotheses:
            assert isinstance(hypothesis, RCAHypothesis)
            assert len(hypothesis.hypothesis_id) > 0
            assert hypothesis.incident_id == incident.incident_id
            assert len(hypothesis.hypothesis_text) > 0
            assert isinstance(hypothesis.confidence_score, (int, float))
            assert 0.0 <= hypothesis.confidence_score <= 1.0
            assert isinstance(hypothesis.supporting_evidence, list)
            assert isinstance(hypothesis.contradicting_evidence, list)
            assert isinstance(hypothesis.investigation_steps, list)
            assert len(hypothesis.investigation_steps) > 0  # Should have investigation steps
            assert isinstance(hypothesis.likelihood_score, (int, float))
            assert 0.0 <= hypothesis.likelihood_score <= 1.0
            assert isinstance(hypothesis.generated_at, datetime)
        
        # Verify hypotheses are stored
        if hypotheses:
            assert incident.incident_id in self.analyzer.rca_hypotheses
            stored_hypotheses = self.analyzer.rca_hypotheses[incident.incident_id]
            assert len(stored_hypotheses) == len(hypotheses)
        
        # Verify hypotheses are ranked by confidence * likelihood
        if len(hypotheses) > 1:
            for i in range(len(hypotheses) - 1):
                current_score = hypotheses[i].confidence_score * hypotheses[i].likelihood_score
                next_score = hypotheses[i + 1].confidence_score * hypotheses[i + 1].likelihood_score
                assert current_score >= next_score  # Should be sorted in descending order
        
        # Test incident response workflow optimization
        if incident.end_time:  # Only for resolved incidents
            historical_incidents = [incident]  # Use current incident as historical data
            workflow = self.analyzer.optimize_incident_response_workflow(
                incident_type="general", 
                historical_incidents=historical_incidents
            )
            
            # Verify workflow structure
            assert len(workflow.workflow_id) > 0
            assert workflow.incident_type == "general"
            assert isinstance(workflow.response_steps, list)
            assert len(workflow.response_steps) > 0
            assert isinstance(workflow.estimated_resolution_time, int)
            assert workflow.estimated_resolution_time > 0
            assert isinstance(workflow.required_roles, list)
            assert len(workflow.required_roles) > 0
            assert isinstance(workflow.escalation_triggers, list)
            assert isinstance(workflow.communication_plan, dict)
            assert isinstance(workflow.success_criteria, list)
            assert len(workflow.success_criteria) > 0
            assert isinstance(workflow.optimization_recommendations, list)
    
    @given(st.text(min_size=3, max_size=20), st.lists(system_metric_strategy(), min_size=20, max_size=200))
    @settings(max_examples=20, deadline=60000)  # 60 second deadline for performance analysis
    def test_property_16_performance_pattern_analysis(self, service_name, metrics):
        """
        **Feature: ai-cybersecurity-platform, Property 16: Performance Pattern Analysis**
        
        For any performance metrics and usage patterns, the system should analyze trends 
        and generate scaling recommendations with cost and performance trade-offs
        
        **Validates: Requirements 3.4**
        """
        assume(len(service_name) > 0)
        assume(len(metrics) >= 20)
        
        # Ensure some metrics belong to the service
        for i in range(min(10, len(metrics))):
            metrics[i].service_name = service_name
        
        # Perform performance analysis
        performance_analysis = self.analyzer.analyze_performance_patterns(
            service_name=service_name,
            metrics=metrics,
            baseline_period_days=7
        )
        
        # Verify performance analysis structure
        assert isinstance(performance_analysis, PerformanceAnalysis)
        assert len(performance_analysis.analysis_id) > 0
        assert performance_analysis.service_name == service_name
        assert isinstance(performance_analysis.analysis_period, tuple)
        assert len(performance_analysis.analysis_period) == 2
        assert isinstance(performance_analysis.analysis_period[0], datetime)
        assert isinstance(performance_analysis.analysis_period[1], datetime)
        assert performance_analysis.analysis_period[0] < performance_analysis.analysis_period[1]
        
        # Verify baseline and current metrics
        assert isinstance(performance_analysis.baseline_metrics, dict)
        assert isinstance(performance_analysis.current_metrics, dict)
        
        # Verify all metric values are reasonable
        for metric_type, value in performance_analysis.baseline_metrics.items():
            assert isinstance(metric_type, SystemMetricType)
            assert isinstance(value, (int, float))
            assert value >= 0  # Metrics should be non-negative
        
        for metric_type, value in performance_analysis.current_metrics.items():
            assert isinstance(metric_type, SystemMetricType)
            assert isinstance(value, (int, float))
            assert value >= 0  # Metrics should be non-negative
        
        # Verify performance trends
        assert isinstance(performance_analysis.performance_trends, dict)
        for metric_name, trend_info in performance_analysis.performance_trends.items():
            assert isinstance(trend_info, dict)
            if 'direction' in trend_info:
                assert trend_info['direction'] in ['increasing', 'decreasing']
            if 'slope' in trend_info:
                assert isinstance(trend_info['slope'], (int, float))
            if 'strength' in trend_info:
                assert isinstance(trend_info['strength'], (int, float))
                assert trend_info['strength'] >= 0
        
        # Verify bottleneck analysis
        assert isinstance(performance_analysis.bottleneck_analysis, dict)
        for bottleneck_name, bottleneck_info in performance_analysis.bottleneck_analysis.items():
            assert isinstance(bottleneck_info, dict)
            if 'severity' in bottleneck_info:
                assert bottleneck_info['severity'] in ['low', 'medium', 'high']
            if 'change_percentage' in bottleneck_info:
                assert isinstance(bottleneck_info['change_percentage'], (int, float))
        
        # Verify scaling recommendations
        assert isinstance(performance_analysis.scaling_recommendations, list)
        for recommendation in performance_analysis.scaling_recommendations:
            assert isinstance(recommendation, str)
            assert len(recommendation) > 0
        
        # Verify optimization opportunities
        assert isinstance(performance_analysis.optimization_opportunities, list)
        for opportunity in performance_analysis.optimization_opportunities:
            assert isinstance(opportunity, str)
            assert len(opportunity) > 0
        
        # Verify analysis timestamp
        assert isinstance(performance_analysis.analysis_timestamp, datetime)
        time_diff = datetime.now() - performance_analysis.analysis_timestamp
        assert time_diff.total_seconds() < 300  # Analysis completed within 5 minutes
        
        # Verify analysis is stored
        assert performance_analysis.analysis_id in self.analyzer.performance_analyses
        stored_analysis = self.analyzer.performance_analyses[performance_analysis.analysis_id]
        assert stored_analysis.service_name == service_name
    
    @given(st.lists(system_metric_strategy(), min_size=50, max_size=200))
    @settings(max_examples=10, deadline=90000)  # 90 second deadline for comprehensive analysis
    def test_comprehensive_reliability_analysis_consistency(self, metrics):
        """
        Test that comprehensive reliability analysis produces consistent results
        """
        assume(len(metrics) >= 50)
        
        # Ensure we have multiple services and metric types
        services = ['service-a', 'service-b', 'service-c']
        metric_types = list(SystemMetricType)
        
        for i, metric in enumerate(metrics[:30]):  # Assign services to first 30 metrics
            metric.service_name = services[i % len(services)]
            metric.metric_type = metric_types[i % len(metric_types)]
        
        # Perform reliability pattern analysis
        patterns = self.analyzer.analyze_reliability_patterns(metrics)
        
        # Perform performance analysis for each service
        performance_analyses = []
        for service in services:
            service_metrics = [m for m in metrics if m.service_name == service]
            if len(service_metrics) >= 10:  # Need sufficient metrics
                analysis = self.analyzer.analyze_performance_patterns(service, metrics)
                performance_analyses.append(analysis)
        
        # Verify consistency across analyses
        assert isinstance(patterns, list)
        assert isinstance(performance_analyses, list)
        
        # Verify all patterns have consistent structure
        pattern_types = set()
        for pattern in patterns:
            pattern_types.add(pattern.pattern_type)
            assert pattern.confidence_score >= 0.0
            assert pattern.confidence_score <= 1.0
        
        # Verify pattern types are valid
        valid_pattern_types = {'degradation', 'spike', 'oscillation', 'trend'}
        assert pattern_types.issubset(valid_pattern_types)
        
        # Verify performance analyses are consistent
        for analysis in performance_analyses:
            assert analysis.service_name in services
            assert len(analysis.scaling_recommendations) >= 0
            assert len(analysis.optimization_opportunities) >= 0
        
        # Verify stored data consistency
        assert len(self.analyzer.reliability_patterns) == len(patterns)
        assert len(self.analyzer.performance_analyses) == len(performance_analyses)
    
    @given(st.lists(incident_event_strategy(), min_size=2, max_size=5))
    @settings(max_examples=10, deadline=120000)  # 120 second deadline for multiple incidents
    def test_multiple_incident_analysis_consistency(self, incidents):
        """
        Test that analyzing multiple incidents produces consistent results
        """
        assume(len(incidents) >= 2)
        assume(len(set(incident.incident_id for incident in incidents)) == len(incidents))  # Unique IDs
        
        all_hypotheses = []
        
        for incident in incidents:
            assume(len(incident.incident_id) > 0)
            assume(len(incident.affected_services) > 0)
            
            hypotheses = self.analyzer.generate_rca_hypotheses(incident)
            all_hypotheses.extend(hypotheses)
        
        # Verify all hypotheses are properly structured
        for hypothesis in all_hypotheses:
            assert isinstance(hypothesis, RCAHypothesis)
            assert len(hypothesis.hypothesis_id) > 0
            assert len(hypothesis.hypothesis_text) > 0
            assert 0.0 <= hypothesis.confidence_score <= 1.0
            assert 0.0 <= hypothesis.likelihood_score <= 1.0
            assert isinstance(hypothesis.supporting_evidence, list)
            assert isinstance(hypothesis.investigation_steps, list)
            assert len(hypothesis.investigation_steps) > 0
        
        # Verify hypotheses are stored for each incident
        for incident in incidents:
            if incident.incident_id in self.analyzer.rca_hypotheses:
                stored_hypotheses = self.analyzer.rca_hypotheses[incident.incident_id]
                assert len(stored_hypotheses) >= 0
                
                # Verify each stored hypothesis is properly structured
                for hypothesis in stored_hypotheses:
                    assert hypothesis.incident_id == incident.incident_id
        
        # Verify hypothesis uniqueness within each incident
        for incident in incidents:
            if incident.incident_id in self.analyzer.rca_hypotheses:
                hypotheses = self.analyzer.rca_hypotheses[incident.incident_id]
                hypothesis_ids = [h.hypothesis_id for h in hypotheses]
                assert len(hypothesis_ids) == len(set(hypothesis_ids))  # All unique


class ReliabilityIntelligenceStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for Reliability Intelligence
    
    This tests the system behavior across multiple operations and state transitions
    """
    
    def __init__(self):
        super().__init__()
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = ReliabilityIntelligenceAnalyzer(
            metrics_storage_path=str(Path(self.temp_dir) / "metrics"),
            incidents_storage_path=str(Path(self.temp_dir) / "incidents"),
            analysis_db_path=str(Path(self.temp_dir) / "analysis" / "reliability_analysis.db")
        )
        
        self.analyzed_patterns = set()
        self.analyzed_incidents = set()
        self.performance_analyses = set()
    
    def teardown(self):
        """Clean up test environment"""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @rule(metrics=st.lists(system_metric_strategy(), min_size=10, max_size=50))
    def analyze_patterns(self, metrics):
        """Analyze reliability patterns"""
        assume(len(metrics) >= 10)
        
        patterns = self.analyzer.analyze_reliability_patterns(metrics)
        
        # Track analyzed patterns
        for pattern in patterns:
            self.analyzed_patterns.add(pattern.pattern_id)
        
        # Verify patterns are stored
        for pattern in patterns:
            assert pattern.pattern_id in self.analyzer.reliability_patterns
    
    @rule(incident=incident_event_strategy())
    def analyze_incident(self, incident):
        """Analyze an incident for RCA hypotheses"""
        assume(len(incident.incident_id) > 0)
        assume(len(incident.affected_services) > 0)
        assume(incident.incident_id not in self.analyzed_incidents)
        
        hypotheses = self.analyzer.generate_rca_hypotheses(incident)
        
        # Track analyzed incident
        self.analyzed_incidents.add(incident.incident_id)
        
        # Verify hypotheses are stored
        if hypotheses:
            assert incident.incident_id in self.analyzer.rca_hypotheses
    
    @rule(service_name=st.text(min_size=3, max_size=15), 
          metrics=st.lists(system_metric_strategy(), min_size=20, max_size=100))
    def analyze_performance(self, service_name, metrics):
        """Analyze performance patterns"""
        assume(len(service_name) > 0)
        assume(len(metrics) >= 20)
        
        # Assign some metrics to the service
        for i in range(min(10, len(metrics))):
            metrics[i].service_name = service_name
        
        analysis = self.analyzer.analyze_performance_patterns(service_name, metrics)
        
        # Track performance analysis
        self.performance_analyses.add(analysis.analysis_id)
        
        # Verify analysis is stored
        assert analysis.analysis_id in self.analyzer.performance_analyses
    
    @invariant()
    def analyzer_state_consistency(self):
        """Verify analyzer state remains consistent"""
        # All analyzed patterns should be stored
        for pattern_id in self.analyzed_patterns:
            assert pattern_id in self.analyzer.reliability_patterns
        
        # All analyzed incidents should be stored (if they have hypotheses)
        for incident_id in self.analyzed_incidents:
            # May not have hypotheses if incident had no metrics or timeline events
            if incident_id in self.analyzer.rca_hypotheses:
                hypotheses = self.analyzer.rca_hypotheses[incident_id]
                assert isinstance(hypotheses, list)
        
        # All performance analyses should be stored
        for analysis_id in self.performance_analyses:
            assert analysis_id in self.analyzer.performance_analyses
        
        # Verify data integrity
        for pattern in self.analyzer.reliability_patterns.values():
            assert 0.0 <= pattern.confidence_score <= 1.0
        
        for hypotheses_list in self.analyzer.rca_hypotheses.values():
            for hypothesis in hypotheses_list:
                assert 0.0 <= hypothesis.confidence_score <= 1.0
                assert 0.0 <= hypothesis.likelihood_score <= 1.0


# Test runner for stateful testing
TestReliabilityIntelligenceStateful = ReliabilityIntelligenceStateMachine.TestCase


if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--tb=short"])