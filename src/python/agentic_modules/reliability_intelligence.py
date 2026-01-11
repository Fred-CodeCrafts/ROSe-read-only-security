"""
Reliability Intelligence and Incident Analysis System

This module provides comprehensive reliability pattern analysis, automated RCA
hypothesis generation, performance pattern analysis, and incident response
workflow optimization. It operates in read-only analytical mode.

Requirements: 3.2, 3.3, 3.4, 3.5
"""

import os
import json
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import re
import math

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SystemMetricType(Enum):
    """Types of system metrics"""
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_UTILIZATION = "memory_utilization"
    DISK_UTILIZATION = "disk_utilization"
    NETWORK_THROUGHPUT = "network_throughput"
    RESPONSE_TIME = "response_time"
    ERROR_RATE = "error_rate"
    AVAILABILITY = "availability"
    THROUGHPUT = "throughput"


@dataclass
class SystemMetric:
    """Represents a system metric data point"""
    metric_type: SystemMetricType
    value: float
    timestamp: datetime
    service_name: str
    tags: Dict[str, str]
    unit: str


@dataclass
class IncidentEvent:
    """Represents an incident event"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    affected_services: List[str]
    start_time: datetime
    end_time: Optional[datetime]
    status: str  # 'open', 'investigating', 'resolved', 'closed'
    tags: Dict[str, str]
    metrics_during_incident: List[SystemMetric]
    timeline_events: List[Dict[str, Any]]


@dataclass
class ReliabilityPattern:
    """Represents a reliability pattern identified in the system"""
    pattern_id: str
    pattern_type: str  # 'degradation', 'spike', 'oscillation', 'trend'
    description: str
    affected_metrics: List[SystemMetricType]
    confidence_score: float  # 0.0 to 1.0
    frequency: str  # 'daily', 'weekly', 'monthly', 'irregular'
    impact_assessment: Dict[str, Any]
    predictive_indicators: List[str]
    discovered_at: datetime


@dataclass
class RCAHypothesis:
    """Represents a root cause analysis hypothesis"""
    hypothesis_id: str
    incident_id: str
    hypothesis_text: str
    confidence_score: float  # 0.0 to 1.0
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    investigation_steps: List[str]
    likelihood_score: float  # 0.0 to 1.0
    generated_at: datetime


@dataclass
class PerformanceAnalysis:
    """Represents performance pattern analysis results"""
    analysis_id: str
    service_name: str
    analysis_period: Tuple[datetime, datetime]
    baseline_metrics: Dict[SystemMetricType, float]
    current_metrics: Dict[SystemMetricType, float]
    performance_trends: Dict[str, Any]
    bottleneck_analysis: Dict[str, Any]
    scaling_recommendations: List[str]
    optimization_opportunities: List[str]
    analysis_timestamp: datetime


@dataclass
class IncidentResponseWorkflow:
    """Represents incident response workflow analysis"""
    workflow_id: str
    incident_type: str
    response_steps: List[Dict[str, Any]]
    estimated_resolution_time: int  # minutes
    required_roles: List[str]
    escalation_triggers: List[str]
    communication_plan: Dict[str, Any]
    success_criteria: List[str]
    optimization_recommendations: List[str]
    created_at: datetime


class ReliabilityIntelligenceAnalyzer:
    """
    OSS-First Reliability Intelligence and Incident Analysis System
    
    Provides comprehensive reliability pattern analysis, automated RCA hypothesis
    generation, performance analysis, and incident response optimization.
    """
    
    def __init__(self, 
                 metrics_storage_path: str = "./data/analysis/metrics",
                 incidents_storage_path: str = "./data/analysis/incidents",
                 analysis_db_path: str = "./data/analysis/reliability_analysis.db"):
        """
        Initialize Reliability Intelligence Analyzer
        
        Args:
            metrics_storage_path: Path to metrics data storage
            incidents_storage_path: Path to incidents data storage
            analysis_db_path: Path to analysis database
        """
        self.metrics_storage_path = Path(metrics_storage_path)
        self.incidents_storage_path = Path(incidents_storage_path)
        self.analysis_db_path = Path(analysis_db_path)
        
        # Create storage directories
        self.metrics_storage_path.mkdir(parents=True, exist_ok=True)
        self.incidents_storage_path.mkdir(parents=True, exist_ok=True)
        self.analysis_db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize analysis state
        self.reliability_patterns: Dict[str, ReliabilityPattern] = {}
        self.rca_hypotheses: Dict[str, List[RCAHypothesis]] = {}
        self.performance_analyses: Dict[str, PerformanceAnalysis] = {}
        self.incident_workflows: Dict[str, IncidentResponseWorkflow] = {}
        
        logger.info(f"Reliability Intelligence Analyzer initialized")
    
    def analyze_reliability_patterns(self, 
                                   metrics: List[SystemMetric],
                                   analysis_window_hours: int = 24) -> List[ReliabilityPattern]:
        """
        Analyze system metrics to identify reliability patterns with predictive insights
        
        Args:
            metrics: List of system metrics to analyze
            analysis_window_hours: Time window for pattern analysis
            
        Returns:
            List of identified reliability patterns
        """
        logger.info(f"Analyzing reliability patterns for {len(metrics)} metrics")
        
        patterns = []
        
        # Group metrics by type and service
        grouped_metrics = self._group_metrics_by_type_and_service(metrics)
        
        for (metric_type, service_name), metric_list in grouped_metrics.items():
            # Sort metrics by timestamp
            metric_list.sort(key=lambda m: m.timestamp)
            
            # Analyze for different pattern types
            patterns.extend(self._detect_degradation_patterns(metric_type, service_name, metric_list))
            patterns.extend(self._detect_spike_patterns(metric_type, service_name, metric_list))
            patterns.extend(self._detect_oscillation_patterns(metric_type, service_name, metric_list))
            patterns.extend(self._detect_trend_patterns(metric_type, service_name, metric_list))
        
        # Store patterns
        for pattern in patterns:
            self.reliability_patterns[pattern.pattern_id] = pattern
        
        logger.info(f"Identified {len(patterns)} reliability patterns")
        return patterns
    
    def generate_rca_hypotheses(self, incident: IncidentEvent) -> List[RCAHypothesis]:
        """
        Generate automated RCA hypotheses using AI analysis
        
        Args:
            incident: Incident event to analyze
            
        Returns:
            List of RCA hypotheses with confidence scores
        """
        logger.info(f"Generating RCA hypotheses for incident: {incident.incident_id}")
        
        hypotheses = []
        
        # Analyze metrics during incident
        metric_hypotheses = self._generate_metric_based_hypotheses(incident)
        hypotheses.extend(metric_hypotheses)
        
        # Analyze timeline events
        timeline_hypotheses = self._generate_timeline_based_hypotheses(incident)
        hypotheses.extend(timeline_hypotheses)
        
        # Analyze service dependencies
        dependency_hypotheses = self._generate_dependency_based_hypotheses(incident)
        hypotheses.extend(dependency_hypotheses)
        
        # Analyze historical patterns
        pattern_hypotheses = self._generate_pattern_based_hypotheses(incident)
        hypotheses.extend(pattern_hypotheses)
        
        # Rank hypotheses by confidence and likelihood
        hypotheses.sort(key=lambda h: (h.confidence_score * h.likelihood_score), reverse=True)
        
        # Store hypotheses
        self.rca_hypotheses[incident.incident_id] = hypotheses
        
        logger.info(f"Generated {len(hypotheses)} RCA hypotheses for incident: {incident.incident_id}")
        return hypotheses
    
    def analyze_performance_patterns(self, 
                                   service_name: str,
                                   metrics: List[SystemMetric],
                                   baseline_period_days: int = 7) -> PerformanceAnalysis:
        """
        Analyze performance patterns and generate scaling recommendations
        
        Args:
            service_name: Name of service to analyze
            metrics: List of performance metrics
            baseline_period_days: Days to use for baseline calculation
            
        Returns:
            Performance analysis with scaling recommendations
        """
        logger.info(f"Analyzing performance patterns for service: {service_name}")
        
        # Filter metrics for the service
        service_metrics = [m for m in metrics if m.service_name == service_name]
        
        # Calculate baseline and current metrics
        baseline_end = datetime.now() - timedelta(days=1)
        baseline_start = baseline_end - timedelta(days=baseline_period_days)
        
        baseline_metrics = self._calculate_baseline_metrics(
            service_metrics, baseline_start, baseline_end
        )
        
        current_start = datetime.now() - timedelta(hours=24)
        current_end = datetime.now()
        
        current_metrics = self._calculate_current_metrics(
            service_metrics, current_start, current_end
        )
        
        # Analyze performance trends
        performance_trends = self._analyze_performance_trends(service_metrics)
        
        # Perform bottleneck analysis
        bottleneck_analysis = self._analyze_bottlenecks(service_metrics, baseline_metrics, current_metrics)
        
        # Generate scaling recommendations
        scaling_recommendations = self._generate_scaling_recommendations(
            baseline_metrics, current_metrics, performance_trends, bottleneck_analysis
        )
        
        # Identify optimization opportunities
        optimization_opportunities = self._identify_optimization_opportunities(
            service_metrics, performance_trends, bottleneck_analysis
        )
        
        analysis = PerformanceAnalysis(
            analysis_id=f"perf-{service_name}-{int(datetime.now().timestamp())}",
            service_name=service_name,
            analysis_period=(current_start, current_end),
            baseline_metrics=baseline_metrics,
            current_metrics=current_metrics,
            performance_trends=performance_trends,
            bottleneck_analysis=bottleneck_analysis,
            scaling_recommendations=scaling_recommendations,
            optimization_opportunities=optimization_opportunities,
            analysis_timestamp=datetime.now()
        )
        
        # Store analysis
        self.performance_analyses[analysis.analysis_id] = analysis
        
        logger.info(f"Performance analysis completed for service: {service_name}")
        return analysis
    
    def optimize_incident_response_workflow(self, 
                                          incident_type: str,
                                          historical_incidents: List[IncidentEvent]) -> IncidentResponseWorkflow:
        """
        Analyze and optimize incident response workflows
        
        Args:
            incident_type: Type of incident to optimize workflow for
            historical_incidents: Historical incidents of this type
            
        Returns:
            Optimized incident response workflow
        """
        logger.info(f"Optimizing incident response workflow for type: {incident_type}")
        
        # Analyze historical response patterns
        response_patterns = self._analyze_historical_response_patterns(historical_incidents)
        
        # Generate optimized response steps
        response_steps = self._generate_optimized_response_steps(incident_type, response_patterns)
        
        # Estimate resolution time based on historical data
        estimated_resolution_time = self._estimate_resolution_time(historical_incidents)
        
        # Identify required roles
        required_roles = self._identify_required_roles(incident_type, response_patterns)
        
        # Define escalation triggers
        escalation_triggers = self._define_escalation_triggers(incident_type, response_patterns)
        
        # Create communication plan
        communication_plan = self._create_communication_plan(incident_type, response_patterns)
        
        # Define success criteria
        success_criteria = self._define_success_criteria(incident_type, response_patterns)
        
        # Generate optimization recommendations
        optimization_recommendations = self._generate_workflow_optimization_recommendations(
            incident_type, response_patterns, historical_incidents
        )
        
        workflow = IncidentResponseWorkflow(
            workflow_id=f"workflow-{incident_type}-{int(datetime.now().timestamp())}",
            incident_type=incident_type,
            response_steps=response_steps,
            estimated_resolution_time=estimated_resolution_time,
            required_roles=required_roles,
            escalation_triggers=escalation_triggers,
            communication_plan=communication_plan,
            success_criteria=success_criteria,
            optimization_recommendations=optimization_recommendations,
            created_at=datetime.now()
        )
        
        # Store workflow
        self.incident_workflows[workflow.workflow_id] = workflow
        
        logger.info(f"Incident response workflow optimized for type: {incident_type}")
        return workflow
    
    # Private helper methods for pattern detection
    
    def _group_metrics_by_type_and_service(self, metrics: List[SystemMetric]) -> Dict[Tuple[SystemMetricType, str], List[SystemMetric]]:
        """Group metrics by type and service"""
        grouped = {}
        for metric in metrics:
            key = (metric.metric_type, metric.service_name)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(metric)
        return grouped
    
    def _detect_degradation_patterns(self, metric_type: SystemMetricType, service_name: str, 
                                   metrics: List[SystemMetric]) -> List[ReliabilityPattern]:
        """Detect performance degradation patterns"""
        patterns = []
        
        if len(metrics) < 10:  # Need sufficient data points
            return patterns
        
        values = [m.value for m in metrics]
        
        # Calculate moving average to detect degradation
        window_size = min(5, len(values) // 2)
        moving_averages = []
        
        for i in range(len(values) - window_size + 1):
            avg = sum(values[i:i + window_size]) / window_size
            moving_averages.append(avg)
        
        # Detect degradation (increasing trend for error rates, response times)
        if len(moving_averages) >= 3:
            recent_avg = sum(moving_averages[-3:]) / 3
            early_avg = sum(moving_averages[:3]) / 3
            
            degradation_threshold = 0.2  # 20% increase
            
            if metric_type in [SystemMetricType.ERROR_RATE, SystemMetricType.RESPONSE_TIME]:
                if recent_avg > early_avg * (1 + degradation_threshold):
                    pattern = ReliabilityPattern(
                        pattern_id=f"degradation-{metric_type.value}-{service_name}-{int(datetime.now().timestamp())}",
                        pattern_type="degradation",
                        description=f"Performance degradation detected in {metric_type.value} for {service_name}",
                        affected_metrics=[metric_type],
                        confidence_score=min(0.9, (recent_avg - early_avg) / early_avg),
                        frequency="irregular",
                        impact_assessment={
                            "severity": "medium" if recent_avg < early_avg * 1.5 else "high",
                            "affected_service": service_name,
                            "degradation_percentage": ((recent_avg - early_avg) / early_avg) * 100
                        },
                        predictive_indicators=[
                            f"Gradual increase in {metric_type.value}",
                            "Moving average trending upward",
                            "Recent values consistently above baseline"
                        ],
                        discovered_at=datetime.now()
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _detect_spike_patterns(self, metric_type: SystemMetricType, service_name: str, 
                             metrics: List[SystemMetric]) -> List[ReliabilityPattern]:
        """Detect spike patterns in metrics"""
        patterns = []
        
        if len(metrics) < 5:
            return patterns
        
        values = [m.value for m in metrics]
        mean_value = statistics.mean(values)
        std_dev = statistics.stdev(values) if len(values) > 1 else 0
        
        if std_dev == 0:
            return patterns
        
        # Detect spikes (values > mean + 2*std_dev)
        spike_threshold = mean_value + (2 * std_dev)
        spikes = [i for i, v in enumerate(values) if v > spike_threshold]
        
        if len(spikes) >= 2:  # Multiple spikes detected
            pattern = ReliabilityPattern(
                pattern_id=f"spike-{metric_type.value}-{service_name}-{int(datetime.now().timestamp())}",
                pattern_type="spike",
                description=f"Spike pattern detected in {metric_type.value} for {service_name}",
                affected_metrics=[metric_type],
                confidence_score=min(0.9, len(spikes) / len(values)),
                frequency="irregular",
                impact_assessment={
                    "severity": "medium",
                    "affected_service": service_name,
                    "spike_count": len(spikes),
                    "max_spike_value": max(values[i] for i in spikes),
                    "spike_threshold": spike_threshold
                },
                predictive_indicators=[
                    f"Values exceeding {spike_threshold:.2f} threshold",
                    f"Standard deviation: {std_dev:.2f}",
                    f"Spike frequency: {len(spikes)}/{len(values)} data points"
                ],
                discovered_at=datetime.now()
            )
            patterns.append(pattern)
        
        return patterns
    
    def _detect_oscillation_patterns(self, metric_type: SystemMetricType, service_name: str, 
                                   metrics: List[SystemMetric]) -> List[ReliabilityPattern]:
        """Detect oscillation patterns in metrics"""
        patterns = []
        
        if len(metrics) < 10:
            return patterns
        
        values = [m.value for m in metrics]
        
        # Simple oscillation detection: count direction changes
        direction_changes = 0
        for i in range(2, len(values)):
            prev_direction = values[i-1] - values[i-2]
            curr_direction = values[i] - values[i-1]
            
            if prev_direction * curr_direction < 0:  # Direction change
                direction_changes += 1
        
        # High number of direction changes indicates oscillation
        oscillation_threshold = len(values) * 0.3  # 30% of data points
        
        if direction_changes > oscillation_threshold:
            pattern = ReliabilityPattern(
                pattern_id=f"oscillation-{metric_type.value}-{service_name}-{int(datetime.now().timestamp())}",
                pattern_type="oscillation",
                description=f"Oscillation pattern detected in {metric_type.value} for {service_name}",
                affected_metrics=[metric_type],
                confidence_score=min(0.9, direction_changes / len(values)),
                frequency="regular",
                impact_assessment={
                    "severity": "low",
                    "affected_service": service_name,
                    "direction_changes": direction_changes,
                    "oscillation_frequency": direction_changes / len(values)
                },
                predictive_indicators=[
                    f"High frequency of direction changes: {direction_changes}",
                    "Regular up-down pattern in values",
                    "Potential system instability or feedback loops"
                ],
                discovered_at=datetime.now()
            )
            patterns.append(pattern)
        
        return patterns
    
    def _detect_trend_patterns(self, metric_type: SystemMetricType, service_name: str, 
                             metrics: List[SystemMetric]) -> List[ReliabilityPattern]:
        """Detect trend patterns in metrics"""
        patterns = []
        
        if len(metrics) < 5:
            return patterns
        
        values = [m.value for m in metrics]
        
        # Simple linear trend detection using least squares
        n = len(values)
        x_values = list(range(n))
        
        # Calculate slope
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n
        
        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return patterns
        
        slope = numerator / denominator
        
        # Determine trend significance
        trend_threshold = abs(y_mean * 0.1)  # 10% of mean value
        
        if abs(slope) > trend_threshold:
            trend_direction = "increasing" if slope > 0 else "decreasing"
            
            pattern = ReliabilityPattern(
                pattern_id=f"trend-{metric_type.value}-{service_name}-{int(datetime.now().timestamp())}",
                pattern_type="trend",
                description=f"{trend_direction.capitalize()} trend detected in {metric_type.value} for {service_name}",
                affected_metrics=[metric_type],
                confidence_score=min(0.9, abs(slope) / y_mean),
                frequency="continuous",
                impact_assessment={
                    "severity": "medium" if abs(slope) > y_mean * 0.2 else "low",
                    "affected_service": service_name,
                    "trend_direction": trend_direction,
                    "slope": slope,
                    "trend_strength": abs(slope) / y_mean
                },
                predictive_indicators=[
                    f"Linear trend with slope: {slope:.4f}",
                    f"Trend direction: {trend_direction}",
                    f"Trend strength: {abs(slope) / y_mean:.2%}"
                ],
                discovered_at=datetime.now()
            )
            patterns.append(pattern)
        
        return patterns
    
    # Private helper methods for RCA hypothesis generation
    
    def _generate_metric_based_hypotheses(self, incident: IncidentEvent) -> List[RCAHypothesis]:
        """Generate hypotheses based on metrics during incident"""
        hypotheses = []
        
        if not incident.metrics_during_incident:
            return hypotheses
        
        # Analyze metric anomalies
        for metric in incident.metrics_during_incident:
            if metric.metric_type == SystemMetricType.CPU_UTILIZATION and metric.value > 80:
                hypothesis = RCAHypothesis(
                    hypothesis_id=f"rca-cpu-{incident.incident_id}-{int(datetime.now().timestamp())}",
                    incident_id=incident.incident_id,
                    hypothesis_text=f"High CPU utilization ({metric.value}%) on {metric.service_name} may have caused the incident",
                    confidence_score=0.8,
                    supporting_evidence=[
                        f"CPU utilization reached {metric.value}% during incident",
                        f"Service {metric.service_name} was affected",
                        "High CPU can cause service degradation"
                    ],
                    contradicting_evidence=[],
                    investigation_steps=[
                        "Check CPU usage patterns before incident",
                        "Identify processes consuming high CPU",
                        "Review application logs for performance issues",
                        "Check for resource-intensive operations"
                    ],
                    likelihood_score=0.7,
                    generated_at=datetime.now()
                )
                hypotheses.append(hypothesis)
            
            elif metric.metric_type == SystemMetricType.MEMORY_UTILIZATION and metric.value > 85:
                hypothesis = RCAHypothesis(
                    hypothesis_id=f"rca-memory-{incident.incident_id}-{int(datetime.now().timestamp())}",
                    incident_id=incident.incident_id,
                    hypothesis_text=f"High memory utilization ({metric.value}%) on {metric.service_name} may have caused the incident",
                    confidence_score=0.8,
                    supporting_evidence=[
                        f"Memory utilization reached {metric.value}% during incident",
                        f"Service {metric.service_name} was affected",
                        "Memory pressure can cause service instability"
                    ],
                    contradicting_evidence=[],
                    investigation_steps=[
                        "Check memory usage patterns before incident",
                        "Identify memory leaks or excessive allocations",
                        "Review garbage collection logs",
                        "Check for memory-intensive operations"
                    ],
                    likelihood_score=0.75,
                    generated_at=datetime.now()
                )
                hypotheses.append(hypothesis)
            
            elif metric.metric_type == SystemMetricType.ERROR_RATE and metric.value > 5:
                hypothesis = RCAHypothesis(
                    hypothesis_id=f"rca-errors-{incident.incident_id}-{int(datetime.now().timestamp())}",
                    incident_id=incident.incident_id,
                    hypothesis_text=f"High error rate ({metric.value}%) on {metric.service_name} indicates application-level issues",
                    confidence_score=0.9,
                    supporting_evidence=[
                        f"Error rate reached {metric.value}% during incident",
                        f"Service {metric.service_name} was affected",
                        "High error rates directly indicate service problems"
                    ],
                    contradicting_evidence=[],
                    investigation_steps=[
                        "Analyze error logs for common patterns",
                        "Check for recent code deployments",
                        "Review database connection issues",
                        "Investigate external service dependencies"
                    ],
                    likelihood_score=0.9,
                    generated_at=datetime.now()
                )
                hypotheses.append(hypothesis)
        
        return hypotheses
    
    def _generate_timeline_based_hypotheses(self, incident: IncidentEvent) -> List[RCAHypothesis]:
        """Generate hypotheses based on incident timeline"""
        hypotheses = []
        
        # Look for deployment events near incident start
        for event in incident.timeline_events:
            if 'deployment' in event.get('type', '').lower():
                time_diff = abs((event.get('timestamp', incident.start_time) - incident.start_time).total_seconds())
                if time_diff < 3600:  # Within 1 hour
                    hypothesis = RCAHypothesis(
                        hypothesis_id=f"rca-deployment-{incident.incident_id}-{int(datetime.now().timestamp())}",
                        incident_id=incident.incident_id,
                        hypothesis_text=f"Recent deployment may have introduced the issue causing this incident",
                        confidence_score=0.8,
                        supporting_evidence=[
                            f"Deployment occurred {time_diff/60:.1f} minutes before incident",
                            "Timing correlation between deployment and incident",
                            "Deployments are common sources of incidents"
                        ],
                        contradicting_evidence=[],
                        investigation_steps=[
                            "Review deployment changes and diff",
                            "Check deployment logs for errors",
                            "Verify rollback procedures",
                            "Compare pre/post deployment metrics"
                        ],
                        likelihood_score=0.7,
                        generated_at=datetime.now()
                    )
                    hypotheses.append(hypothesis)
        
        return hypotheses
    
    def _generate_dependency_based_hypotheses(self, incident: IncidentEvent) -> List[RCAHypothesis]:
        """Generate hypotheses based on service dependencies"""
        hypotheses = []
        
        # Analyze affected services for dependency patterns
        if len(incident.affected_services) > 1:
            hypothesis = RCAHypothesis(
                hypothesis_id=f"rca-cascade-{incident.incident_id}-{int(datetime.now().timestamp())}",
                incident_id=incident.incident_id,
                hypothesis_text="Cascading failure from upstream service dependency may have caused this incident",
                confidence_score=0.6,
                supporting_evidence=[
                    f"Multiple services affected: {', '.join(incident.affected_services)}",
                    "Multi-service incidents often indicate dependency issues",
                    "Cascading failures are common in microservice architectures"
                ],
                contradicting_evidence=[],
                investigation_steps=[
                    "Map service dependency graph",
                    "Identify upstream services that failed first",
                    "Check for circuit breaker activations",
                    "Review service-to-service communication logs"
                ],
                likelihood_score=0.6,
                generated_at=datetime.now()
            )
            hypotheses.append(hypothesis)
        
        return hypotheses
    
    def _generate_pattern_based_hypotheses(self, incident: IncidentEvent) -> List[RCAHypothesis]:
        """Generate hypotheses based on historical patterns"""
        hypotheses = []
        
        # Check for similar incidents in the past
        similar_patterns = [p for p in self.reliability_patterns.values() 
                          if any(service in incident.affected_services for service in [p.impact_assessment.get('affected_service')])]
        
        if similar_patterns:
            pattern = similar_patterns[0]  # Use most relevant pattern
            hypothesis = RCAHypothesis(
                hypothesis_id=f"rca-pattern-{incident.incident_id}-{int(datetime.now().timestamp())}",
                incident_id=incident.incident_id,
                hypothesis_text=f"Historical {pattern.pattern_type} pattern suggests similar root cause",
                confidence_score=pattern.confidence_score * 0.7,  # Reduce confidence for historical correlation
                supporting_evidence=[
                    f"Similar {pattern.pattern_type} pattern previously identified",
                    f"Pattern affects same service: {pattern.impact_assessment.get('affected_service')}",
                    f"Pattern confidence: {pattern.confidence_score:.2f}"
                ],
                contradicting_evidence=[],
                investigation_steps=[
                    f"Review historical {pattern.pattern_type} pattern analysis",
                    "Compare current metrics with pattern indicators",
                    "Check if previous mitigation strategies apply",
                    "Validate pattern predictive indicators"
                ],
                likelihood_score=pattern.confidence_score * 0.6,
                generated_at=datetime.now()
            )
            hypotheses.append(hypothesis)
        
        return hypotheses
    
    # Private helper methods for performance analysis
    
    def _calculate_baseline_metrics(self, metrics: List[SystemMetric], 
                                  start_time: datetime, end_time: datetime) -> Dict[SystemMetricType, float]:
        """Calculate baseline metrics for a time period"""
        baseline_metrics = {}
        
        # Filter metrics to baseline period
        baseline_period_metrics = [
            m for m in metrics 
            if start_time <= m.timestamp <= end_time
        ]
        
        # Group by metric type
        grouped = {}
        for metric in baseline_period_metrics:
            if metric.metric_type not in grouped:
                grouped[metric.metric_type] = []
            grouped[metric.metric_type].append(metric.value)
        
        # Calculate averages
        for metric_type, values in grouped.items():
            if values:
                baseline_metrics[metric_type] = statistics.mean(values)
        
        return baseline_metrics
    
    def _calculate_current_metrics(self, metrics: List[SystemMetric], 
                                 start_time: datetime, end_time: datetime) -> Dict[SystemMetricType, float]:
        """Calculate current metrics for a time period"""
        return self._calculate_baseline_metrics(metrics, start_time, end_time)
    
    def _analyze_performance_trends(self, metrics: List[SystemMetric]) -> Dict[str, Any]:
        """Analyze performance trends in metrics"""
        trends = {}
        
        # Group by metric type
        grouped = {}
        for metric in metrics:
            if metric.metric_type not in grouped:
                grouped[metric.metric_type] = []
            grouped[metric.metric_type].append((metric.timestamp, metric.value))
        
        # Analyze trends for each metric type
        for metric_type, data_points in grouped.items():
            if len(data_points) < 3:
                continue
            
            # Sort by timestamp
            data_points.sort(key=lambda x: x[0])
            values = [dp[1] for dp in data_points]
            
            # Calculate trend
            n = len(values)
            x_values = list(range(n))
            x_mean = sum(x_values) / n
            y_mean = sum(values) / n
            
            numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
            denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
            
            if denominator != 0:
                slope = numerator / denominator
                trend_direction = "increasing" if slope > 0 else "decreasing"
                trend_strength = abs(slope) / y_mean if y_mean != 0 else 0
                
                trends[metric_type.value] = {
                    "direction": trend_direction,
                    "slope": slope,
                    "strength": trend_strength,
                    "data_points": len(values)
                }
        
        return trends
    
    def _analyze_bottlenecks(self, metrics: List[SystemMetric], 
                           baseline_metrics: Dict[SystemMetricType, float],
                           current_metrics: Dict[SystemMetricType, float]) -> Dict[str, Any]:
        """Analyze system bottlenecks"""
        bottlenecks = {}
        
        # Compare current vs baseline for each metric
        for metric_type in SystemMetricType:
            if metric_type in baseline_metrics and metric_type in current_metrics:
                baseline = baseline_metrics[metric_type]
                current = current_metrics[metric_type]
                
                if baseline > 0:
                    change_percentage = ((current - baseline) / baseline) * 100
                    
                    # Identify bottlenecks based on significant increases
                    if metric_type in [SystemMetricType.CPU_UTILIZATION, SystemMetricType.MEMORY_UTILIZATION]:
                        if change_percentage > 20:  # 20% increase
                            bottlenecks[metric_type.value] = {
                                "severity": "high" if change_percentage > 50 else "medium",
                                "baseline": baseline,
                                "current": current,
                                "change_percentage": change_percentage,
                                "description": f"{metric_type.value} increased by {change_percentage:.1f}%"
                            }
                    
                    elif metric_type in [SystemMetricType.RESPONSE_TIME, SystemMetricType.ERROR_RATE]:
                        if change_percentage > 15:  # 15% increase
                            bottlenecks[metric_type.value] = {
                                "severity": "high" if change_percentage > 40 else "medium",
                                "baseline": baseline,
                                "current": current,
                                "change_percentage": change_percentage,
                                "description": f"{metric_type.value} increased by {change_percentage:.1f}%"
                            }
        
        return bottlenecks
    
    def _generate_scaling_recommendations(self, baseline_metrics: Dict[SystemMetricType, float],
                                        current_metrics: Dict[SystemMetricType, float],
                                        performance_trends: Dict[str, Any],
                                        bottleneck_analysis: Dict[str, Any]) -> List[str]:
        """Generate scaling recommendations based on analysis"""
        recommendations = []
        
        # CPU-based recommendations
        if SystemMetricType.CPU_UTILIZATION in current_metrics:
            cpu_usage = current_metrics[SystemMetricType.CPU_UTILIZATION]
            if cpu_usage > 80:
                recommendations.append(f"Scale up CPU resources - current utilization: {cpu_usage:.1f}%")
            elif cpu_usage > 70 and 'cpu_utilization' in performance_trends:
                trend = performance_trends['cpu_utilization']
                if trend['direction'] == 'increasing':
                    recommendations.append(f"Consider proactive CPU scaling - trending upward at {cpu_usage:.1f}%")
        
        # Memory-based recommendations
        if SystemMetricType.MEMORY_UTILIZATION in current_metrics:
            memory_usage = current_metrics[SystemMetricType.MEMORY_UTILIZATION]
            if memory_usage > 85:
                recommendations.append(f"Scale up memory resources - current utilization: {memory_usage:.1f}%")
            elif memory_usage > 75 and 'memory_utilization' in performance_trends:
                trend = performance_trends['memory_utilization']
                if trend['direction'] == 'increasing':
                    recommendations.append(f"Consider proactive memory scaling - trending upward at {memory_usage:.1f}%")
        
        # Response time recommendations
        if SystemMetricType.RESPONSE_TIME in current_metrics and SystemMetricType.RESPONSE_TIME in baseline_metrics:
            current_rt = current_metrics[SystemMetricType.RESPONSE_TIME]
            baseline_rt = baseline_metrics[SystemMetricType.RESPONSE_TIME]
            if current_rt > baseline_rt * 1.5:
                recommendations.append(f"Consider horizontal scaling - response time increased {((current_rt - baseline_rt) / baseline_rt) * 100:.1f}%")
        
        # Bottleneck-based recommendations
        for bottleneck_type, bottleneck_info in bottleneck_analysis.items():
            if bottleneck_info['severity'] == 'high':
                recommendations.append(f"Address {bottleneck_type} bottleneck - {bottleneck_info['description']}")
        
        # Default recommendations if no specific issues found
        if not recommendations:
            recommendations.append("System performance appears stable - continue monitoring")
        
        return recommendations
    
    def _identify_optimization_opportunities(self, metrics: List[SystemMetric],
                                           performance_trends: Dict[str, Any],
                                           bottleneck_analysis: Dict[str, Any]) -> List[str]:
        """Identify optimization opportunities"""
        opportunities = []
        
        # Analyze resource utilization patterns
        cpu_metrics = [m for m in metrics if m.metric_type == SystemMetricType.CPU_UTILIZATION]
        if cpu_metrics:
            cpu_values = [m.value for m in cpu_metrics]
            avg_cpu = statistics.mean(cpu_values)
            
            if avg_cpu < 30:
                opportunities.append("CPU utilization is low - consider rightsizing instances")
            elif avg_cpu > 80:
                opportunities.append("CPU utilization is high - optimize application performance or scale up")
        
        # Analyze response time patterns
        if 'response_time' in performance_trends:
            rt_trend = performance_trends['response_time']
            if rt_trend['direction'] == 'increasing' and rt_trend['strength'] > 0.1:
                opportunities.append("Response time trending upward - investigate performance optimizations")
        
        # Analyze error rate patterns
        if 'error_rate' in performance_trends:
            error_trend = performance_trends['error_rate']
            if error_trend['direction'] == 'increasing':
                opportunities.append("Error rate trending upward - investigate and fix underlying issues")
        
        # Bottleneck-specific opportunities
        for bottleneck_type, bottleneck_info in bottleneck_analysis.items():
            if bottleneck_type == 'memory_utilization':
                opportunities.append("Optimize memory usage - implement caching or reduce memory footprint")
            elif bottleneck_type == 'cpu_utilization':
                opportunities.append("Optimize CPU usage - profile application for performance improvements")
        
        return opportunities
    
    # Private helper methods for incident response workflow optimization
    
    def _analyze_historical_response_patterns(self, incidents: List[IncidentEvent]) -> Dict[str, Any]:
        """Analyze historical incident response patterns"""
        patterns = {
            "average_resolution_time": 0,
            "common_response_steps": [],
            "escalation_patterns": [],
            "success_factors": [],
            "failure_factors": []
        }
        
        if not incidents:
            return patterns
        
        # Calculate average resolution time
        resolution_times = []
        for incident in incidents:
            if incident.end_time:
                resolution_time = (incident.end_time - incident.start_time).total_seconds() / 60  # minutes
                resolution_times.append(resolution_time)
        
        if resolution_times:
            patterns["average_resolution_time"] = statistics.mean(resolution_times)
        
        # Analyze common response patterns (simplified)
        patterns["common_response_steps"] = [
            "Initial assessment and triage",
            "Identify affected services and impact",
            "Implement immediate mitigation",
            "Root cause investigation",
            "Permanent fix implementation",
            "Post-incident review"
        ]
        
        return patterns
    
    def _generate_optimized_response_steps(self, incident_type: str, 
                                         response_patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate optimized response steps"""
        base_steps = [
            {
                "step": 1,
                "title": "Incident Detection and Alert",
                "description": "Automated detection and initial alert generation",
                "estimated_time": 2,
                "responsible_role": "monitoring_system",
                "automation_level": "fully_automated"
            },
            {
                "step": 2,
                "title": "Initial Triage and Assessment",
                "description": "Assess incident severity and impact scope",
                "estimated_time": 5,
                "responsible_role": "on_call_engineer",
                "automation_level": "semi_automated"
            },
            {
                "step": 3,
                "title": "Stakeholder Notification",
                "description": "Notify relevant stakeholders based on severity",
                "estimated_time": 3,
                "responsible_role": "incident_commander",
                "automation_level": "automated"
            },
            {
                "step": 4,
                "title": "Immediate Mitigation",
                "description": "Implement immediate fixes to restore service",
                "estimated_time": 15,
                "responsible_role": "engineering_team",
                "automation_level": "manual"
            },
            {
                "step": 5,
                "title": "Root Cause Investigation",
                "description": "Investigate and identify root cause",
                "estimated_time": 30,
                "responsible_role": "engineering_team",
                "automation_level": "manual"
            },
            {
                "step": 6,
                "title": "Permanent Fix Implementation",
                "description": "Implement permanent solution",
                "estimated_time": 60,
                "responsible_role": "engineering_team",
                "automation_level": "manual"
            },
            {
                "step": 7,
                "title": "Verification and Monitoring",
                "description": "Verify fix and monitor for stability",
                "estimated_time": 15,
                "responsible_role": "engineering_team",
                "automation_level": "semi_automated"
            },
            {
                "step": 8,
                "title": "Post-Incident Review",
                "description": "Conduct post-mortem and document lessons learned",
                "estimated_time": 120,
                "responsible_role": "incident_commander",
                "automation_level": "manual"
            }
        ]
        
        return base_steps
    
    def _estimate_resolution_time(self, incidents: List[IncidentEvent]) -> int:
        """Estimate resolution time based on historical data"""
        if not incidents:
            return 120  # Default 2 hours
        
        resolution_times = []
        for incident in incidents:
            if incident.end_time:
                resolution_time = (incident.end_time - incident.start_time).total_seconds() / 60  # minutes
                resolution_times.append(resolution_time)
        
        if resolution_times:
            return int(statistics.mean(resolution_times))
        
        return 120  # Default 2 hours
    
    def _identify_required_roles(self, incident_type: str, response_patterns: Dict[str, Any]) -> List[str]:
        """Identify required roles for incident response"""
        return [
            "incident_commander",
            "on_call_engineer",
            "engineering_team_lead",
            "site_reliability_engineer",
            "security_engineer",
            "communications_lead"
        ]
    
    def _define_escalation_triggers(self, incident_type: str, response_patterns: Dict[str, Any]) -> List[str]:
        """Define escalation triggers"""
        return [
            "Incident not resolved within 1 hour",
            "Multiple services affected",
            "Customer-facing impact detected",
            "Security implications identified",
            "Data loss or corruption suspected",
            "External vendor involvement required"
        ]
    
    def _create_communication_plan(self, incident_type: str, response_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Create communication plan for incident response"""
        return {
            "internal_channels": ["slack_incident_channel", "email_distribution_list"],
            "external_channels": ["status_page", "customer_notifications"],
            "update_frequency": {
                "high_severity": "every_15_minutes",
                "medium_severity": "every_30_minutes",
                "low_severity": "every_hour"
            },
            "stakeholder_groups": {
                "engineering": ["engineering_team", "sre_team"],
                "management": ["engineering_manager", "vp_engineering"],
                "customer_facing": ["customer_success", "support_team"],
                "external": ["customers", "partners"]
            }
        }
    
    def _define_success_criteria(self, incident_type: str, response_patterns: Dict[str, Any]) -> List[str]:
        """Define success criteria for incident resolution"""
        return [
            "All affected services restored to normal operation",
            "Error rates returned to baseline levels",
            "Response times within acceptable thresholds",
            "No customer-reported issues for 30 minutes",
            "Monitoring alerts cleared",
            "Root cause identified and documented",
            "Permanent fix implemented and verified"
        ]
    
    def _generate_workflow_optimization_recommendations(self, incident_type: str,
                                                      response_patterns: Dict[str, Any],
                                                      historical_incidents: List[IncidentEvent]) -> List[str]:
        """Generate workflow optimization recommendations"""
        recommendations = []
        
        # Analyze resolution times
        avg_resolution = response_patterns.get("average_resolution_time", 120)
        if avg_resolution > 180:  # More than 3 hours
            recommendations.append("Consider implementing automated rollback procedures to reduce resolution time")
        
        # Analyze incident frequency
        if len(historical_incidents) > 5:
            recommendations.append("High incident frequency detected - implement preventive measures and monitoring")
        
        # General optimization recommendations
        recommendations.extend([
            "Implement automated incident detection and alerting",
            "Create runbooks for common incident types",
            "Establish clear escalation procedures and contact lists",
            "Implement automated rollback capabilities where possible",
            "Conduct regular incident response training and drills",
            "Maintain up-to-date service dependency maps",
            "Implement comprehensive monitoring and observability",
            "Establish post-incident review processes"
        ])
        
        return recommendations