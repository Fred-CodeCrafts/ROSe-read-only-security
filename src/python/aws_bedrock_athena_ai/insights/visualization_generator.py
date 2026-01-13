"""
Visualization generator for security posture and analysis results.

This module creates clear visualizations and charts for security data,
tailored for different audiences and use cases.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, Threat, ThreatSeverity, ThreatType
from aws_bedrock_athena_ai.insights.models import Visualization, VisualizationType, AudienceType, ActionPlan

logger = logging.getLogger(__name__)


class VisualizationGenerator:
    """Generates security visualizations and dashboards"""
    
    def __init__(self):
        self.color_schemes = {
            "risk": {
                "critical": "#DC2626",  # Red
                "high": "#EA580C",      # Orange
                "medium": "#D97706",    # Amber
                "low": "#16A34A",       # Green
                "info": "#2563EB"       # Blue
            },
            "status": {
                "resolved": "#16A34A",
                "in_progress": "#D97706", 
                "open": "#DC2626",
                "monitoring": "#2563EB"
            }
        }
    
    def create_risk_dashboard(
        self, 
        analysis: ThreatAnalysis, 
        audience: AudienceType = AudienceType.EXECUTIVE
    ) -> Visualization:
        """
        Create risk dashboard visualization.
        
        Args:
            analysis: Threat analysis results
            audience: Target audience for the visualization
            
        Returns:
            Visualization: Risk dashboard configuration
        """
        logger.info(f"Creating risk dashboard for {audience.value} audience")
        
        # Prepare risk metrics data
        risk_data = {
            "overall_risk_score": analysis.risk_assessment.overall_risk_score,
            "risk_level": analysis.risk_assessment.risk_level.value,
            "threat_distribution": {
                "critical": analysis.risk_assessment.critical_threats,
                "high": analysis.risk_assessment.high_threats,
                "medium": analysis.risk_assessment.medium_threats,
                "low": analysis.risk_assessment.low_threats
            },
            "mitigation_coverage": analysis.risk_assessment.mitigation_coverage,
            "trend": analysis.risk_assessment.trend,
            "risk_factors": analysis.risk_assessment.risk_factors
        }
        
        # Configure dashboard based on audience
        if audience == AudienceType.EXECUTIVE:
            config = self._create_executive_risk_dashboard_config(risk_data)
        else:
            config = self._create_technical_risk_dashboard_config(risk_data)
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title=f"Security Risk Dashboard - {audience.value.title()}",
            viz_type=VisualizationType.RISK_DASHBOARD,
            description=f"Comprehensive security risk overview for {audience.value} stakeholders",
            data=risk_data,
            config=config,
            audience=audience,
            priority=1
        )
    
    def generate_threat_timeline(
        self, 
        threats: List[Threat], 
        audience: AudienceType = AudienceType.TECHNICAL
    ) -> Visualization:
        """
        Generate threat timeline visualization.
        
        Args:
            threats: List of identified threats
            audience: Target audience
            
        Returns:
            Visualization: Threat timeline chart
        """
        logger.info(f"Generating threat timeline for {len(threats)} threats")
        
        # Prepare timeline data
        timeline_data = []
        
        for threat in threats:
            if threat.first_seen and threat.last_seen:
                timeline_data.append({
                    "threat_id": threat.threat_id,
                    "title": threat.title,
                    "severity": threat.severity.value,
                    "type": threat.threat_type.value,
                    "start_time": threat.first_seen.isoformat(),
                    "end_time": threat.last_seen.isoformat(),
                    "duration_hours": (threat.last_seen - threat.first_seen).total_seconds() / 3600,
                    "affected_systems": threat.affected_systems,
                    "confidence": threat.confidence
                })
        
        # Sort by severity and start time
        timeline_data.sort(key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4),
            x["start_time"]
        ))
        
        config = {
            "chart_type": "timeline",
            "x_axis": {
                "field": "start_time",
                "type": "datetime",
                "title": "Timeline"
            },
            "y_axis": {
                "field": "title",
                "type": "categorical",
                "title": "Security Threats"
            },
            "color": {
                "field": "severity",
                "scale": self.color_schemes["risk"]
            },
            "tooltip": [
                "title", "severity", "type", "duration_hours", 
                "affected_systems", "confidence"
            ],
            "height": max(400, len(timeline_data) * 30),
            "interactive": True
        }
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title="Security Threat Timeline",
            viz_type=VisualizationType.THREAT_TIMELINE,
            description="Chronological view of security threats and incidents",
            data={"timeline": timeline_data},
            config=config,
            audience=audience,
            priority=2
        )
    
    def create_security_posture_chart(
        self, 
        analysis: ThreatAnalysis, 
        audience: AudienceType = AudienceType.EXECUTIVE
    ) -> Visualization:
        """
        Create security posture visualization.
        
        Args:
            analysis: Threat analysis results
            audience: Target audience
            
        Returns:
            Visualization: Security posture chart
        """
        logger.info("Creating security posture visualization")
        
        # Calculate security posture metrics
        posture_data = {
            "overall_score": analysis.risk_assessment.overall_risk_score,
            "categories": {
                "threat_detection": min(10, 10 - (analysis.risk_assessment.critical_threats * 2)),
                "vulnerability_management": min(10, analysis.risk_assessment.mitigation_coverage / 10),
                "incident_response": 7.5,  # Would be calculated from actual data
                "access_control": 8.0,     # Would be calculated from actual data
                "monitoring": 6.5,         # Would be calculated from actual data
                "compliance": 7.8          # Would be calculated from actual data
            },
            "trend_data": self._generate_trend_data(analysis),
            "benchmark_comparison": {
                "industry_average": 6.5,
                "our_score": 10 - analysis.risk_assessment.overall_risk_score,
                "percentile": 65 if analysis.risk_assessment.overall_risk_score < 5 else 35
            }
        }
        
        if audience == AudienceType.EXECUTIVE:
            config = self._create_executive_posture_config(posture_data)
        else:
            config = self._create_technical_posture_config(posture_data)
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title="Security Posture Assessment",
            viz_type=VisualizationType.SECURITY_POSTURE,
            description="Comprehensive security posture evaluation across key domains",
            data=posture_data,
            config=config,
            audience=audience,
            priority=1
        )
    
    def generate_compliance_status_chart(
        self, 
        analysis: ThreatAnalysis,
        frameworks: Optional[List[str]] = None
    ) -> Visualization:
        """
        Generate compliance status visualization.
        
        Args:
            analysis: Threat analysis results
            frameworks: List of compliance frameworks to assess
            
        Returns:
            Visualization: Compliance status chart
        """
        if not frameworks:
            frameworks = ["SOC2", "ISO27001", "NIST", "PCI-DSS", "GDPR"]
        
        logger.info(f"Generating compliance status for frameworks: {frameworks}")
        
        # Calculate compliance scores (simplified model)
        compliance_data = {}
        base_score = max(50, 100 - (analysis.risk_assessment.overall_risk_score * 10))
        
        for framework in frameworks:
            # Adjust score based on framework requirements
            framework_score = base_score + self._get_framework_adjustment(framework, analysis)
            compliance_data[framework] = {
                "score": min(100, max(0, framework_score)),
                "status": "compliant" if framework_score >= 80 else "non_compliant",
                "gaps": self._identify_compliance_gaps(framework, analysis),
                "last_assessment": datetime.now().isoformat()
            }
        
        config = {
            "chart_type": "horizontal_bar",
            "x_axis": {
                "field": "score",
                "type": "quantitative",
                "title": "Compliance Score (%)",
                "scale": {"domain": [0, 100]}
            },
            "y_axis": {
                "field": "framework",
                "type": "categorical",
                "title": "Compliance Framework"
            },
            "color": {
                "field": "status",
                "scale": {
                    "compliant": "#16A34A",
                    "non_compliant": "#DC2626"
                }
            },
            "tooltip": ["framework", "score", "status", "gaps"],
            "height": 300,
            "annotations": [
                {
                    "type": "line",
                    "value": 80,
                    "label": "Compliance Threshold",
                    "color": "#6B7280"
                }
            ]
        }
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title="Compliance Status Dashboard",
            viz_type=VisualizationType.COMPLIANCE_STATUS,
            description="Current compliance status across security frameworks",
            data={"compliance": compliance_data},
            config=config,
            audience=AudienceType.COMPLIANCE,
            priority=1
        )
    
    def create_trend_analysis_chart(
        self, 
        analysis: ThreatAnalysis,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Visualization:
        """
        Create security trend analysis visualization.
        
        Args:
            analysis: Current threat analysis
            historical_data: Historical security metrics
            
        Returns:
            Visualization: Trend analysis chart
        """
        logger.info("Creating security trend analysis")
        
        # Generate trend data (mock historical data if not provided)
        if not historical_data:
            historical_data = self._generate_mock_historical_data(analysis)
        
        trend_data = {
            "risk_score_trend": historical_data,
            "threat_count_trend": self._generate_threat_count_trend(analysis),
            "mitigation_coverage_trend": self._generate_coverage_trend(analysis),
            "current_metrics": {
                "risk_score": analysis.risk_assessment.overall_risk_score,
                "threat_count": len(analysis.threats_identified),
                "mitigation_coverage": analysis.risk_assessment.mitigation_coverage
            }
        }
        
        config = {
            "chart_type": "multi_line",
            "x_axis": {
                "field": "date",
                "type": "datetime",
                "title": "Time Period"
            },
            "y_axis": {
                "title": "Security Metrics"
            },
            "lines": [
                {
                    "field": "risk_score",
                    "color": "#DC2626",
                    "label": "Risk Score"
                },
                {
                    "field": "threat_count",
                    "color": "#EA580C",
                    "label": "Active Threats"
                },
                {
                    "field": "mitigation_coverage",
                    "color": "#16A34A",
                    "label": "Mitigation Coverage %"
                }
            ],
            "height": 400,
            "interactive": True,
            "legend": True
        }
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title="Security Metrics Trend Analysis",
            viz_type=VisualizationType.TREND_ANALYSIS,
            description="Historical trends in security metrics and risk posture",
            data=trend_data,
            config=config,
            audience=AudienceType.TECHNICAL,
            priority=3
        )
    
    def generate_action_plan_visualization(self, action_plan: ActionPlan) -> Visualization:
        """
        Generate action plan visualization.
        
        Args:
            action_plan: Security action plan
            
        Returns:
            Visualization: Action plan chart
        """
        logger.info(f"Generating action plan visualization for {action_plan.total_items} items")
        
        # Prepare action plan data for visualization
        plan_data = {
            "items_by_priority": {
                "critical": action_plan.critical_items,
                "high": action_plan.high_priority_items,
                "medium": action_plan.total_items - action_plan.critical_items - action_plan.high_priority_items,
                "low": 0  # Calculated from remaining items
            },
            "timeline_data": self._prepare_timeline_data(action_plan),
            "cost_breakdown": self._prepare_cost_breakdown(action_plan),
            "milestones": action_plan.milestones
        }
        
        config = {
            "chart_type": "gantt",
            "x_axis": {
                "field": "timeline",
                "type": "datetime",
                "title": "Implementation Timeline"
            },
            "y_axis": {
                "field": "action_item",
                "type": "categorical",
                "title": "Action Items"
            },
            "color": {
                "field": "priority",
                "scale": self.color_schemes["risk"]
            },
            "tooltip": [
                "action_item", "priority", "owner", "estimated_effort", 
                "deadline", "cost_estimate"
            ],
            "height": max(400, action_plan.total_items * 25),
            "milestones": True
        }
        
        return Visualization(
            viz_id=str(uuid.uuid4()),
            title="Security Action Plan Timeline",
            viz_type=VisualizationType.RISK_DASHBOARD,  # Reusing dashboard type
            description="Implementation timeline and priorities for security improvements",
            data=plan_data,
            config=config,
            audience=AudienceType.OPERATIONS,
            priority=2
        )
    
    # Helper methods for dashboard configurations
    def _create_executive_risk_dashboard_config(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive-focused risk dashboard configuration"""
        return {
            "layout": "executive",
            "components": [
                {
                    "type": "risk_gauge",
                    "title": "Overall Risk Score",
                    "data_field": "overall_risk_score",
                    "max_value": 10,
                    "color_zones": [
                        {"min": 0, "max": 3, "color": "#16A34A"},
                        {"min": 3, "max": 6, "color": "#D97706"},
                        {"min": 6, "max": 10, "color": "#DC2626"}
                    ]
                },
                {
                    "type": "donut_chart",
                    "title": "Threat Distribution",
                    "data_field": "threat_distribution",
                    "colors": self.color_schemes["risk"]
                },
                {
                    "type": "progress_bar",
                    "title": "Mitigation Coverage",
                    "data_field": "mitigation_coverage",
                    "target": 90
                },
                {
                    "type": "trend_indicator",
                    "title": "Security Trend",
                    "data_field": "trend"
                }
            ],
            "style": {
                "theme": "executive",
                "font_size": "large",
                "emphasis": "business_impact"
            }
        }
    
    def _create_technical_risk_dashboard_config(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create technical-focused risk dashboard configuration"""
        return {
            "layout": "technical",
            "components": [
                {
                    "type": "detailed_metrics",
                    "title": "Risk Metrics",
                    "data_field": "overall_risk_score",
                    "show_calculations": True
                },
                {
                    "type": "stacked_bar",
                    "title": "Threat Severity Distribution",
                    "data_field": "threat_distribution",
                    "colors": self.color_schemes["risk"]
                },
                {
                    "type": "risk_factors_list",
                    "title": "Risk Factors",
                    "data_field": "risk_factors"
                },
                {
                    "type": "coverage_heatmap",
                    "title": "Control Coverage",
                    "data_field": "mitigation_coverage"
                }
            ],
            "style": {
                "theme": "technical",
                "font_size": "medium",
                "emphasis": "technical_details"
            }
        }
    
    def _create_executive_posture_config(self, posture_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive security posture configuration"""
        return {
            "chart_type": "radar",
            "categories": list(posture_data["categories"].keys()),
            "values": list(posture_data["categories"].values()),
            "max_value": 10,
            "benchmark_line": posture_data["benchmark_comparison"]["industry_average"],
            "colors": {
                "our_score": "#2563EB",
                "benchmark": "#6B7280"
            },
            "labels": {
                "threat_detection": "Threat Detection",
                "vulnerability_management": "Vulnerability Mgmt",
                "incident_response": "Incident Response",
                "access_control": "Access Control",
                "monitoring": "Security Monitoring",
                "compliance": "Compliance"
            }
        }
    
    def _create_technical_posture_config(self, posture_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create technical security posture configuration"""
        return {
            "chart_type": "detailed_radar",
            "categories": list(posture_data["categories"].keys()),
            "values": list(posture_data["categories"].values()),
            "max_value": 10,
            "show_grid": True,
            "show_values": True,
            "benchmark_comparison": True,
            "trend_indicators": True,
            "drill_down": True
        }
    
    # Helper methods for data generation
    def _generate_trend_data(self, analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Generate mock trend data for security posture"""
        trend_data = []
        base_date = datetime.now() - timedelta(days=90)
        
        for i in range(13):  # 13 weeks of data
            date = base_date + timedelta(weeks=i)
            # Simulate improving trend
            risk_score = max(2.0, analysis.risk_assessment.overall_risk_score + (i * -0.2))
            
            trend_data.append({
                "date": date.isoformat(),
                "risk_score": risk_score,
                "threat_count": max(0, len(analysis.threats_identified) - i),
                "mitigation_coverage": min(100, analysis.risk_assessment.mitigation_coverage + (i * 2))
            })
        
        return trend_data
    
    def _get_framework_adjustment(self, framework: str, analysis: ThreatAnalysis) -> float:
        """Get framework-specific score adjustment"""
        adjustments = {
            "SOC2": -5 if analysis.risk_assessment.critical_threats > 0 else 5,
            "ISO27001": 0,  # Baseline
            "NIST": 3 if analysis.risk_assessment.mitigation_coverage > 80 else -3,
            "PCI-DSS": -10 if analysis.risk_assessment.critical_threats > 2 else 0,
            "GDPR": -8 if any("data" in rf.lower() for rf in analysis.risk_assessment.risk_factors) else 2
        }
        return adjustments.get(framework, 0)
    
    def _identify_compliance_gaps(self, framework: str, analysis: ThreatAnalysis) -> List[str]:
        """Identify compliance gaps for a framework"""
        gaps = {
            "SOC2": ["Access control review", "Change management"],
            "ISO27001": ["Risk assessment documentation", "Security awareness training"],
            "NIST": ["Incident response procedures", "Vulnerability management"],
            "PCI-DSS": ["Network segmentation", "Encryption at rest"],
            "GDPR": ["Data protection impact assessment", "Breach notification procedures"]
        }
        
        base_gaps = gaps.get(framework, ["General security controls"])
        
        # Add gaps based on analysis
        if analysis.risk_assessment.critical_threats > 0:
            base_gaps.append("Critical vulnerability remediation")
        
        if analysis.risk_assessment.mitigation_coverage < 80:
            base_gaps.append("Security control coverage")
        
        return base_gaps[:3]  # Limit to 3 gaps
    
    def _generate_mock_historical_data(self, analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Generate mock historical data for trend analysis"""
        historical_data = []
        base_date = datetime.now() - timedelta(days=180)
        
        for i in range(25):  # 25 weeks of data
            date = base_date + timedelta(weeks=i)
            
            # Simulate realistic security metrics evolution
            risk_score = max(1.0, min(10.0, 
                analysis.risk_assessment.overall_risk_score + 
                (i * -0.1) + (0.5 * (i % 4 - 2))  # Some volatility
            ))
            
            historical_data.append({
                "date": date.isoformat(),
                "risk_score": round(risk_score, 1),
                "threat_count": max(0, len(analysis.threats_identified) + (i % 3 - 1)),
                "mitigation_coverage": min(100, max(40, 
                    analysis.risk_assessment.mitigation_coverage - (25 - i) * 2
                ))
            })
        
        return historical_data
    
    def _generate_threat_count_trend(self, analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Generate threat count trend data"""
        return self._generate_mock_historical_data(analysis)  # Reuse for simplicity
    
    def _generate_coverage_trend(self, analysis: ThreatAnalysis) -> List[Dict[str, Any]]:
        """Generate mitigation coverage trend data"""
        return self._generate_mock_historical_data(analysis)  # Reuse for simplicity
    
    def _prepare_timeline_data(self, action_plan: ActionPlan) -> List[Dict[str, Any]]:
        """Prepare timeline data for action plan visualization"""
        timeline_data = []
        
        for item in action_plan.action_items:
            timeline_data.append({
                "action_item": item.title,
                "priority": item.priority,
                "owner": item.owner,
                "start_date": datetime.now().isoformat(),
                "end_date": item.deadline.isoformat() if item.deadline else None,
                "estimated_effort": item.estimated_effort,
                "cost_estimate": item.cost_estimate,
                "category": item.category
            })
        
        return timeline_data
    
    def _prepare_cost_breakdown(self, action_plan: ActionPlan) -> Dict[str, Any]:
        """Prepare cost breakdown data"""
        cost_by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cost_by_category = {}
        
        for item in action_plan.action_items:
            if item.cost_estimate:
                cost_by_priority[item.priority] += item.cost_estimate
                
                if item.category not in cost_by_category:
                    cost_by_category[item.category] = 0
                cost_by_category[item.category] += item.cost_estimate
        
        return {
            "by_priority": cost_by_priority,
            "by_category": cost_by_category,
            "total": action_plan.total_cost_estimate or 0
        }