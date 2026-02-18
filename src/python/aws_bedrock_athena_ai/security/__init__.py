"""
Security and compliance module for AI Security Analyst.

This module provides:
- IAM-based authentication and authorization
- Data privacy and sensitive data redaction
- Audit logging and monitoring
- Access controls and compliance features
"""

from aws_bedrock_athena_ai.security.iam_auth import IAMAuthenticator
from aws_bedrock_athena_ai.security.data_redactor import SensitiveDataRedactor
from aws_bedrock_athena_ai.security.audit_logger import AuditLogger
from aws_bedrock_athena_ai.security.access_control import AccessController

__all__ = [
    'IAMAuthenticator',
    'SensitiveDataRedactor', 
    'AuditLogger',
    'AccessController'
]