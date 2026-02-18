"""
Data models for security and compliance features.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class AccessLevel(Enum):
    """Access levels for different types of operations."""
    READ_ONLY = "read_only"
    QUERY = "query"
    ADMIN = "admin"
    AUDIT = "audit"


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ResourceType(Enum):
    """Types of resources that can be accessed."""
    S3_BUCKET = "s3_bucket"
    ATHENA_DATABASE = "athena_database"
    ATHENA_TABLE = "athena_table"
    BEDROCK_MODEL = "bedrock_model"
    SECURITY_DATA = "security_data"
    ANALYSIS_RESULT = "analysis_result"
    CONFIGURATION = "configuration"


class AuditEventType(Enum):
    """Types of audit events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    QUERY_EXECUTION = "query_execution"
    ANALYSIS_REQUEST = "analysis_request"
    CONFIGURATION_CHANGE = "configuration_change"
    ERROR = "error"


@dataclass
class IAMPrincipal:
    """Represents an IAM principal (user, role, or service)."""
    principal_type: str  # user, role, assumed-role, federated-user
    principal_id: str
    arn: str
    account_id: str
    user_name: Optional[str] = None
    role_name: Optional[str] = None
    session_name: Optional[str] = None


@dataclass
class AccessRequest:
    """Represents an access request for authorization."""
    principal: IAMPrincipal
    resource: str
    action: str
    context: Dict[str, Any]
    timestamp: datetime
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AccessDecision:
    """Result of an access control decision."""
    allowed: bool
    reason: str
    required_permissions: List[str]
    missing_permissions: List[str]
    conditions_met: bool
    decision_time: datetime


@dataclass
class AuditEvent:
    """Represents an audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    principal: IAMPrincipal
    resource: str
    action: str
    result: str  # success, failure, error
    details: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class RedactionRule:
    """Rule for redacting sensitive data."""
    pattern_name: str
    pattern_regex: str
    replacement: str
    data_classification: DataClassification
    enabled: bool = True


@dataclass
class RedactionResult:
    """Result of data redaction operation."""
    original_text: str
    redacted_text: str
    redactions_made: List[Dict[str, Any]]
    classification_level: DataClassification
    processing_time_ms: float


@dataclass
class SecurityContext:
    """Security context for a request."""
    principal: IAMPrincipal
    access_level: AccessLevel
    permissions: List[str]
    session_id: str
    request_id: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    mfa_authenticated: bool = False
    session_duration: Optional[int] = None


@dataclass
class ComplianceCheck:
    """Result of a compliance check."""
    check_name: str
    passed: bool
    details: str
    recommendations: List[str]
    severity: str  # low, medium, high, critical
    timestamp: datetime