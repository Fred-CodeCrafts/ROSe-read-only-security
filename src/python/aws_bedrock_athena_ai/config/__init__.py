"""
Configuration module for AI Security Analyst

Provides AWS configuration management and client setup.
"""

from aws_bedrock_athena_ai.config.aws_config import AWSConfig, AWSClientManager, create_aws_clients, validate_aws_setup

__all__ = [
    'AWSConfig',
    'AWSClientManager', 
    'create_aws_clients',
    'validate_aws_setup'
]