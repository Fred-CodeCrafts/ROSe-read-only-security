"""
Onboarding and demonstration system for AI Security Analyst.

This module provides quick-start capabilities for new users to get immediate
value from the system within 5 minutes of setup.
"""

from aws_bedrock_athena_ai.onboarding.quick_start import QuickStartManager
from aws_bedrock_athena_ai.onboarding.sample_data import SampleDataGenerator
from aws_bedrock_athena_ai.onboarding.format_detector import DataFormatDetector
from aws_bedrock_athena_ai.onboarding.tutorial_system import TutorialSystem
from aws_bedrock_athena_ai.onboarding.demo_scenarios import DemoScenarios

__all__ = [
    'QuickStartManager',
    'SampleDataGenerator', 
    'DataFormatDetector',
    'TutorialSystem',
    'DemoScenarios'
]