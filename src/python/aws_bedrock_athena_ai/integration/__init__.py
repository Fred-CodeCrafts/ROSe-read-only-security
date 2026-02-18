"""
Integration module for AI Security Analyst.

This module provides the main pipeline integration that wires together
all components with comprehensive error handling and graceful degradation.
"""

from aws_bedrock_athena_ai.integration.ai_security_analyst_pipeline import AISecurityAnalystPipeline, PipelineResult
from aws_bedrock_athena_ai.integration.error_handler import ErrorHandler, ErrorResponse, ErrorCategory, ErrorSeverity, GracefulDegradation

__all__ = [
    'AISecurityAnalystPipeline',
    'PipelineResult', 
    'ErrorHandler',
    'ErrorResponse',
    'ErrorCategory',
    'ErrorSeverity',
    'GracefulDegradation'
]