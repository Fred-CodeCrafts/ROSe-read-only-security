"""
Test suite for the Expert Reasoning Engine components.

Tests threat analysis, risk assessment, and recommendation generation
using both unit tests and integration tests.
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from reasoning_engine.expert_reasoning_engine import ExpertReasoningEngine
from reasoning_engine.threat_analyzer import ThreatAnalyzer
from reasoning_engine.risk_assessor import RiskAssessor
from reasoning_engine.recommendation_generator import RecommendationGenerator
from reasoning_engine.models import (
    Threat, ThreatType, ThreatSeverity, Evidence, Pattern,
    RiskAssessment, RiskLevel, 