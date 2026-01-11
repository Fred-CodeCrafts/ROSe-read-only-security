"""
OSS Data Intelligence Layer

This module provides comprehensive data analysis, governance, and access pattern intelligence
using open-source tools (DuckDB, MinIO, SOPS) with optional AWS upgrade paths.
"""

from .oss_data_intelligence import OSSDataIntelligence
from .models import (
    AccessLog,
    AccessPatternReport,
    DataAsset,
    GovernanceAnalysisReport,
    PolicyRecommendationReport,
    DataClassification,
    AccessType,
    PolicyType,
    LocalTag,
    LocalPolicy,
    LocalDataAccess,
    OSSDataAsset
)

__all__ = [
    'OSSDataIntelligence',
    'AccessLog',
    'AccessPatternReport', 
    'DataAsset',
    'GovernanceAnalysisReport',
    'PolicyRecommendationReport',
    'DataClassification',
    'AccessType',
    'PolicyType',
    'LocalTag',
    'LocalPolicy',
    'LocalDataAccess',
    'OSSDataAsset'
]