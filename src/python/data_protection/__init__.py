"""
Data Protection Module

This module provides comprehensive data protection capabilities including:
- Automatic log redaction for PII and secrets
- Synthetic data validation
- Real-time data classification
- Security pattern detection
"""

from .log_redactor import LogRedactor
from .synthetic_data_validator import SyntheticDataValidator
from .data_classifier import DataClassifier
from .access_analyzer import AccessPatternAnalyzer, BlastRadiusAnalyzer
from .models import (
    RedactionResult, DataClassification, ValidationResult,
    AccessPattern, BlastRadiusAssessment, RedactionType, DataProtectionPolicy
)

__all__ = [
    'LogRedactor',
    'SyntheticDataValidator', 
    'DataClassifier',
    'AccessPatternAnalyzer',
    'BlastRadiusAnalyzer',
    'RedactionResult',
    'DataClassification',
    'ValidationResult',
    'AccessPattern',
    'BlastRadiusAssessment',
    'RedactionType',
    'DataProtectionPolicy'
]