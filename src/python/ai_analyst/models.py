"""
Data models for the OSS AI Security Analyst

This module defines the data structures used throughout the security analysis system.
All models are designed for read-only analysis operations with comprehensive reporting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum


class SeverityLevel(Enum):
    """Security finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityEventType(Enum):
    """Types of security events that can be detected"""
    SECRET_EXPOSURE = "secret_exposure"
    INSECURE_CONFIG = "insecure_config"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    MISSING_SECURITY_CONTROL = "missing_security_control"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    COMPLIANCE_VIOLATION = "compliance_violation"


class ComplianceStatus(Enum):
    """SDD compliance status levels"""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass
class FileMetadata:
    """Metadata about a file in the repository"""
    path: str
    size: int
    last_modified: datetime
    file_type: str
    security_relevant: bool = False
    contains_secrets: bool = False
    permissions: Optional[str] = None


@dataclass
class CommitInfo:
    """Information about a git commit"""
    hash: str
    author: str
    timestamp: datetime
    message: str
    files_changed: List[str]
    security_relevant: bool = False


@dataclass
class Dependency:
    """Information about a project dependency"""
    name: str
    version: str
    package_manager: str  # pip, npm, go mod, etc.
    security_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    license: Optional[str] = None
    last_updated: Optional[datetime] = None


@dataclass
class SecurityFinding:
    """A security issue discovered during analysis"""
    id: str
    type: SecurityEventType
    severity: SeverityLevel
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    confidence: float = 0.0
    remediation_advice: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityAssessment:
    """Overall security posture assessment"""
    overall_score: float  # 0.0 to 1.0
    risk_level: SeverityLevel
    findings_summary: Dict[SeverityLevel, int]
    recommendations: List[str]
    assessment_date: datetime = field(default_factory=datetime.now)


@dataclass
class SDDArtifacts:
    """Spec-Driven Development artifacts"""
    requirements_md: Optional[str] = None
    design_md: Optional[str] = None
    tasks_md: Optional[str] = None
    requirements_exists: bool = False
    design_exists: bool = False
    tasks_exists: bool = False


@dataclass
class ComplianceViolation:
    """A violation of SDD or steering file policies"""
    rule_id: str
    rule_name: str
    severity: SeverityLevel
    description: str
    expected: str
    actual: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class SteeringFilePolicy:
    """A policy defined in steering files"""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    enforcement_level: str  # "error", "warning", "info"
    applicable_files: List[str] = field(default_factory=list)


@dataclass
class OSSProjectContext:
    """Complete project context for OSS analysis"""
    repo_path: str
    repo_structure: Dict[str, FileMetadata]
    git_history: List[CommitInfo]
    dependencies: List[Dependency]
    security_posture: SecurityAssessment
    compliance_status: ComplianceStatus
    sdd_artifacts: SDDArtifacts
    steering_policies: List[SteeringFilePolicy] = field(default_factory=list)
    
    # OSS-specific configurations
    ollama_model_config: Dict[str, Any] = field(default_factory=dict)
    local_permissions: Dict[str, Any] = field(default_factory=dict)
    prometheus_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Optional AWS upgrade fields (documented but not used by default)
    aws_config_compliance: Optional[Dict[str, Any]] = None
    bedrock_model_config: Optional[Dict[str, Any]] = None
    
    last_analyzed: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityPatternMatch:
    """A detected security pattern (good or bad)"""
    pattern_id: str
    pattern_name: str
    pattern_type: str  # "security_pattern" or "anti_pattern"
    description: str
    file_path: str
    line_range: tuple[int, int]
    confidence: float
    impact_assessment: str
    remediation_suggestion: Optional[str] = None


@dataclass
class TextualRecommendation:
    """A human-readable recommendation for security improvement"""
    id: str
    title: str
    description: str
    priority: SeverityLevel
    category: str  # "security", "compliance", "best_practice"
    implementation_steps: List[str]
    estimated_effort: str  # "low", "medium", "high"
    references: List[str] = field(default_factory=list)
    applies_to_files: List[str] = field(default_factory=list)


@dataclass
class AnalysisContext:
    """Context information for analysis operations"""
    analysis_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    analyzer_version: str = "1.0.0"
    ollama_model: Optional[str] = None
    analysis_type: str = "security_analysis"
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def mark_completed(self):
        """Mark the analysis as completed"""
        self.completed_at = datetime.now()
    
    @property
    def duration(self) -> Optional[float]:
        """Get analysis duration in seconds"""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


@dataclass
class LocalRemediationAction:
    """A remediation action that can be taken locally (read-only analysis)"""
    action_id: str
    action_type: str  # "file_change", "config_update", "dependency_update"
    description: str
    target_file: Optional[str] = None
    proposed_change: Optional[str] = None
    risk_level: SeverityLevel = SeverityLevel.LOW
    requires_human_review: bool = True
    
    # Note: This is for analysis and recommendation only
    # No actual changes are made to the system


@dataclass
class LocalTag:
    """A tag for local resource classification"""
    key: str
    value: str
    category: str = "general"


@dataclass
class LocalPolicy:
    """A local policy for data governance"""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    enforcement_level: str
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class LocalDataAccess:
    """Record of local data access for audit purposes"""
    access_id: str
    user: str
    resource: str
    action: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    details: Optional[str] = None


@dataclass
class DataClassification:
    """Classification of data sensitivity"""
    level: str  # "public", "internal", "confidential", "restricted"
    categories: List[str]  # "pii", "financial", "health", etc.
    retention_period: Optional[str] = None
    encryption_required: bool = False


# Type aliases for common collections
SecurityFindings = List[SecurityFinding]
TextualRecommendations = List[TextualRecommendation]
SecurityPatternMatches = List[SecurityPatternMatch]
ComplianceViolations = List[ComplianceViolation]