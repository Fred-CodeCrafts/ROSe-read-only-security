"""
Expert Reasoning Engine - AWS Bedrock Integration

This module provides expert-level security analysis using AWS Bedrock foundation models.
It analyzes data retrieved by the Smart Data Detective and provides threat pattern recognition,
risk assessment, and security recommendations.
"""

from aws_bedrock_athena_ai.reasoning_engine.expert_reasoning_engine import ExpertReasoningEngine
from aws_bedrock_athena_ai.reasoning_engine.threat_analyzer import ThreatAnalyzer
from aws_bedrock_athena_ai.reasoning_engine.risk_assessor import RiskAssessor
from aws_bedrock_athena_ai.reasoning_engine.recommendation_generator import RecommendationGenerator
from aws_bedrock_athena_ai.reasoning_engine.models import ThreatAnalysis, Threat, RiskAssessment, Recommendation

__all__ = [
    'ExpertReasoningEngine',
    'ThreatAnalyzer', 
    'RiskAssessor',
    'RecommendationGenerator',
    'ThreatAnalysis',
    'Threat',
    'RiskAssessment', 
    'Recommendation'
]