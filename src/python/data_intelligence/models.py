"""
Data models for OSS Data Intelligence Layer

Defines data structures for access patterns, governance analysis, and policy management
using OSS-first approach with optional AWS upgrade paths.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import json


class DataClassification(Enum):
    """Data classification levels for governance analysis"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AccessType(Enum):
    """Types of data access operations"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class PolicyType(Enum):
    """Types of data governance policies"""
    ACCESS_CONTROL = "access_control"
    RETENTION = "retention"
    ENCRYPTION = "encryption"
    COMPLIANCE = "compliance"


@dataclass
class LocalTag:
    """Local tag for data asset classification"""
    key: str
    value: str
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class LocalPolicy:
    """Local data governance policy"""
    policy_id: str
    policy_type: PolicyType
    name: str
    description: str
    rules: Dict[str, Any]
    tags: List[LocalTag] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    active: bool = True


@dataclass
class LocalDataAccess:
    """Local data access audit record"""
    access_id: str
    user_id: str
    resource_path: str
    access_type: AccessType
    timestamp: datetime
    source_ip: str
    user_agent: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessLog:
    """Access log entry for pattern analysis"""
    timestamp: datetime
    user_id: str
    resource_path: str
    access_type: AccessType
    source_ip: str
    user_agent: str
    success: bool
    response_time_ms: int
    bytes_transferred: int
    tags: List[LocalTag] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataAsset:
    """Data asset for governance analysis"""
    asset_id: str
    name: str
    description: str
    minio_bucket: str
    duckdb_table: str
    local_file_path: str
    classification: DataClassification
    owner: str
    tags: List[LocalTag] = field(default_factory=list)
    policies: List[LocalPolicy] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    size_bytes: int = 0
    record_count: int = 0


@dataclass
class OSSDataAsset:
    """OSS-specific data asset model with encryption and audit capabilities"""
    minio_bucket: str
    duckdb_table: str
    local_file_path: str
    sops_encryption_key: str
    access_tags: List[LocalTag]
    local_policies: List[LocalPolicy]
    data_classification: DataClassification
    access_audit_trail: List[LocalDataAccess]
    
    # Optional AWS upgrade fields
    lake_formation_resource_arn: Optional[str] = None
    s3_location: Optional[str] = None
    kms_key_id: Optional[str] = None


@dataclass
class AccessPattern:
    """Identified access pattern from analysis"""
    pattern_id: str
    pattern_type: str
    description: str
    frequency: int
    users_affected: List[str]
    resources_affected: List[str]
    risk_level: str
    recommendations: List[str]
    confidence_score: float


@dataclass
class AccessPatternReport:
    """Report containing access pattern analysis results"""
    analysis_id: str
    timestamp: datetime
    total_access_events: int
    unique_users: int
    unique_resources: int
    patterns_identified: List[AccessPattern]
    security_recommendations: List[str]
    least_privilege_violations: List[Dict[str, Any]]
    anomalous_access_events: List[AccessLog]
    summary: str


@dataclass
class GovernanceViolation:
    """Data governance policy violation"""
    violation_id: str
    policy_id: str
    resource_path: str
    violation_type: str
    description: str
    severity: str
    detected_at: datetime
    remediation_steps: List[str]


@dataclass
class GovernanceAnalysisReport:
    """Report containing data governance analysis results"""
    analysis_id: str
    timestamp: datetime
    total_assets_analyzed: int
    policies_evaluated: List[str]
    violations_found: List[GovernanceViolation]
    compliance_score: float
    policy_coverage_gaps: List[str]
    recommendations: List[str]
    cross_account_patterns: List[Dict[str, Any]]
    summary: str


@dataclass
class PolicyConflict:
    """Detected policy conflict"""
    conflict_id: str
    conflicting_policies: List[str]
    conflict_type: str
    description: str
    affected_resources: List[str]
    resolution_options: List[str]


@dataclass
class PolicyRecommendation:
    """Policy improvement recommendation"""
    recommendation_id: str
    recommendation_type: str
    title: str
    description: str
    affected_policies: List[str]
    implementation_steps: List[str]
    expected_impact: str
    priority: str


@dataclass
class PolicyRecommendationReport:
    """Report containing policy analysis and recommendations"""
    analysis_id: str
    timestamp: datetime
    policies_analyzed: List[str]
    conflicts_detected: List[PolicyConflict]
    recommendations: List[PolicyRecommendation]
    harmonization_opportunities: List[Dict[str, Any]]
    optimization_suggestions: List[str]
    summary: str


@dataclass
class CrossAccountAccessPattern:
    """Cross-account access pattern for zero-copy optimization"""
    pattern_id: str
    source_account: str
    target_account: str
    resource_type: str
    access_frequency: int
    data_volume_gb: float
    current_copy_operations: int
    zero_copy_feasible: bool
    optimization_potential: str
    implementation_complexity: str
    cost_savings_estimate: float


def serialize_dataclass(obj) -> str:
    """Serialize dataclass to JSON string"""
    if hasattr(obj, '__dataclass_fields__'):
        data = {}
        for field_name, field_def in obj.__dataclass_fields__.items():
            value = getattr(obj, field_name)
            if isinstance(value, datetime):
                data[field_name] = value.isoformat()
            elif isinstance(value, Enum):
                data[field_name] = value.value
            elif isinstance(value, list):
                data[field_name] = [serialize_dataclass(item) if hasattr(item, '__dataclass_fields__') else item for item in value]
            elif hasattr(value, '__dataclass_fields__'):
                data[field_name] = serialize_dataclass(value)
            else:
                data[field_name] = value
        return json.dumps(data, indent=2)
    return str(obj)


def deserialize_datetime(date_str: str) -> datetime:
    """Deserialize ISO format datetime string"""
    return datetime.fromisoformat(date_str.replace('Z', '+00:00'))