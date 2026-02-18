"""
Infrastructure module for AI Security Analyst

Provides AWS infrastructure deployment and management capabilities.
"""

from aws_bedrock_athena_ai.infrastructure.deploy_infrastructure import InfrastructureDeployer

__all__ = [
    'InfrastructureDeployer'
]