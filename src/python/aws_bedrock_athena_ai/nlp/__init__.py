"""
Natural Language Processing module for AI Security Analyst.

This module provides natural language understanding capabilities for security questions,
including intent recognition, context extraction, and query disambiguation.
"""

from aws_bedrock_athena_ai.nlp.simple_interface import SimpleNaturalLanguageInterface
from aws_bedrock_athena_ai.nlp.intent_recognizer import SecurityIntentRecognizer
from aws_bedrock_athena_ai.nlp.context_extractor import SecurityContextExtractor
from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, SecurityEntity, NLPResponse

__all__ = [
    'SimpleNaturalLanguageInterface',
    'SecurityIntentRecognizer',
    'SecurityContextExtractor', 
    'SecurityIntent',
    'QueryContext',
    'SecurityEntity',
    'NLPResponse'
]