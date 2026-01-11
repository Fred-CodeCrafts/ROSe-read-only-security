"""
Data Protection Models

Defines data structures for data protection operations.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum
import datetime


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RedactionType(Enum):
    """Types of redaction patterns"""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"
    PHONE_NUMBER = "phone_number"
    SSN = "ssn"
    PASSWORD = "password"
    TOKEN = "token"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"


@dataclass
class RedactionMatch:
    """Represents a detected pattern that needs redaction"""
    pattern_type: RedactionType
    start_pos: int
    end_pos: int
    original_text: str
    confidence: float


@dataclass
class RedactionResult:
    """Result of log redaction operation"""
    original_text: str
    redacted_text: str
    matches: List[RedactionMatch]
    redaction_count: int
    timestamp: datetime.datetime


@dataclass
class ValidationResult:
    """Result of synthetic data validation"""
    is_synthetic: bool
    confidence_score: float
    detected_real_patterns: List[str]
    validation_errors: List[str]
    timestamp: datetime.datetime


@dataclass
class DataProtectionPolicy:
    """Data protection policy configuration"""
    enable_email_redaction: bool = True
    enable_ip_redaction: bool = True
    enable_phone_redaction: bool = True
    enable_ssn_redaction: bool = True
    enable_aws_key_redaction: bool = True
    enable_password_redaction: bool = True
    enable_token_redaction: bool = True
    enable_credit_card_redaction: bool = True
    enable_api_key_redaction: bool = True
    redaction_placeholder: str = "[REDACTED]"
    min_confidence_threshold: float = 0.8


@dataclass
class AccessPattern:
    """Represents an access pattern for analysis"""
    user_id: str
    resource: str
    action: str
    timestamp: datetime.datetime
    source_ip: str
    user_agent: Optional[str] = None
    success: bool = True
    risk_score: float = 0.0


@dataclass
class BlastRadiusAssessment:
    """Assessment of potential blast radius for security incidents"""
    affected_services: List[str]
    affected_regions: List[str]
    affected_accounts: List[str]
    impact_score: float
    containment_recommendations: List[str]
    estimated_recovery_time: str
    risk_level: str