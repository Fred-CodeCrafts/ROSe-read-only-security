"""
OSS-First AI Security Analyst Package

This package provides comprehensive security analysis capabilities using
open-source tools by default, with optional AWS upgrade paths.

Main Components:
- OSSSecurityAnalyst: Core analysis engine with Ollama integration
- Models: Data structures for analysis results and context
- Reports: Analysis report generation and formatting
"""

from .oss_security_analyst import (
    OSSSecurityAnalyst,
    SecurityAnalysisReport,
    ComplianceAnalysisReport,
    SecurityPatternReport
)

from .models import (
    # Enums
    SeverityLevel,
    SecurityEventType,
    ComplianceStatus,
    
    # Core data models
    SecurityFinding,
    SecurityAssessment,
    SDDArtifacts,
    ComplianceViolation,
    SteeringFilePolicy,
    OSSProjectContext,
    SecurityPatternMatch,
    TextualRecommendation,
    AnalysisContext,
    
    # Supporting models
    FileMetadata,
    CommitInfo,
    Dependency,
    LocalRemediationAction,
    LocalTag,
    LocalPolicy,
    LocalDataAccess,
    DataClassification,
    
    # Type aliases
    SecurityFindings,
    TextualRecommendations,
    SecurityPatternMatches,
    ComplianceViolations
)

__version__ = "1.0.0"
__author__ = "OSS Cybersecurity Platform"

# Default configuration for OSS stack
DEFAULT_CONFIG = {
    "ollama_endpoint": "http://localhost:11434",
    "analysis_db_path": "./data/analysis/analysis_context.db",
    "vector_db_path": "./data/analysis/vector_db",
    "default_model": "llama2",
    "max_analysis_time": 300,  # 5 minutes
    "confidence_threshold": 0.7
}