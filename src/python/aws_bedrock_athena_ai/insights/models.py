"""
Data models for the Instant Insights Generator.

These models define the structure for reports, visualizations, and action plans
generated for different audiences.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class AudienceType(Enum):
    """Target audience types for reports"""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    OPERATIONS = "operations"


class ReportType(Enum):
    """Types of security reports"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILS = "technical_details"
    COMPLIANCE_REPORT = "compliance_report"
    INCIDENT_REPORT = "incident_report"
    RISK_ASSESSMENT = "risk_assessment"


class VisualizationType(Enum):
    """Types of visualizations"""
    RISK_DASHBOARD = "risk_dashboard"
    THREAT_TIMELINE = "threat_timeline"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE_STATUS = "compliance_status"
    TREND_ANALYSIS = "trend_analysis"


@dataclass
class ReportSection:
    """A section within a report"""
    title: str
    content: str
    priority: int = 1  # 1 = highest priority
    audience_specific: bool = True
    charts: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ExecutiveReport:
    """Executive-level security report"""
    report_id: str
    timestamp: datetime
    title: str
    executive_summary: str
    key_findings: List[str]
    business_impact: str
    risk_score: float
    critical_issues: int
    recommendations_summary: List[str]
    cost_benefit_analysis: Dict[str, Any]
    industry_benchmarks: Dict[str, Any]
    sections: List[ReportSection] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)


@dataclass
class TechnicalReport:
    """Technical detailed security report"""
    report_id: str
    timestamp: datetime
    title: str
    technical_summary: str
    detailed_findings: List[Dict[str, Any]]
    threat_details: List[Dict[str, Any]]
    system_analysis: Dict[str, Any]
    remediation_steps: List[Dict[str, Any]]
    technical_recommendations: List[Dict[str, Any]]
    sections: List[ReportSection] = field(default_factory=list)
    appendices: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """Compliance-focused security report"""
    report_id: str
    timestamp: datetime
    title: str
    compliance_summary: str
    framework_assessments: Dict[str, Any]  # SOC2, ISO27001, etc.
    gaps_identified: List[Dict[str, Any]]
    compliance_score: float
    audit_findings: List[Dict[str, Any]]
    remediation_timeline: Dict[str, Any]
    sections: List[ReportSection] = field(default_factory=list)


@dataclass
class Visualization:
    """Security data visualization"""
    viz_id: str
    title: str
    viz_type: VisualizationType
    description: str
    data: Dict[str, Any]
    config: Dict[str, Any]  # Chart configuration
    audience: AudienceType
    priority: int = 1


@dataclass
class ActionItem:
    """Individual action item in an action plan"""
    item_id: str
    title: str
    description: str
    priority: str  # critical, high, medium, low
    category: str
    owner: str
    estimated_effort: str
    deadline: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    business_justification: str = ""
    cost_estimate: Optional[float] = None


@dataclass
class ActionPlan:
    """Prioritized action plan for security improvements"""
    plan_id: str
    timestamp: datetime
    title: str
    summary: str
    total_items: int
    critical_items: int
    high_priority_items: int
    estimated_timeline: str
    total_cost_estimate: Optional[float] = None
    expected_roi: Optional[float] = None
    action_items: List[ActionItem] = field(default_factory=list)
    milestones: List[Dict[str, Any]] = field(default_factory=list)
    success_metrics: List[str] = field(default_factory=list)