"""
Error Handler - Comprehensive error handling and graceful degradation.

This module provides centralized error handling, recovery strategies,
and graceful degradation for the AI Security Analyst pipeline.
"""

import logging
from enum import Enum
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Categories of errors that can occur in the pipeline."""
    NLP_ERROR = "nlp_error"
    DATA_ACCESS_ERROR = "data_access_error"
    AI_ANALYSIS_ERROR = "ai_analysis_error"
    COST_LIMIT_ERROR = "cost_limit_error"
    RESOURCE_ERROR = "resource_error"
    CONFIGURATION_ERROR = "configuration_error"
    NETWORK_ERROR = "network_error"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorResponse:
    """Standardized error response structure."""
    error_id: str
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    user_message: str
    suggestions: List[str]
    recovery_actions: List[str]
    can_retry: bool
    fallback_available: bool
    timestamp: datetime


class ErrorHandler:
    """
    Centralized error handler for the AI Security Analyst pipeline.
    
    Provides error categorization, user-friendly messages, recovery suggestions,
    and graceful degradation strategies.
    """
    
    def __init__(self):
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        
    def handle_error(
        self, 
        error: Exception, 
        context: Optional[Dict[str, Any]] = None
    ) -> ErrorResponse:
        """
        Handle an error and provide appropriate response and recovery options.
        
        Args:
            error: The exception that occurred
            context: Optional context about where the error occurred
            
        Returns:
            ErrorResponse: Structured error response with recovery options
        """
        error_str = str(error)
        error_type = type(error).__name__
        
        # Categorize the error
        category = self._categorize_error(error, error_str, context)
        severity = self._assess_severity(error, category, context)
        
        # Generate user-friendly message and suggestions
        user_message = self._generate_user_message(category, error_str, context)
        suggestions = self._generate_suggestions(category, error_str, context)
        recovery_actions = self._generate_recovery_actions(category, error_str, context)
        
        # Determine retry and fallback options
        can_retry = self._can_retry(category, error_type)
        fallback_available = self._has_fallback(category, context)
        
        error_response = ErrorResponse(
            error_id=f"err_{hash(error_str) % 10000:04d}",
            category=category,
            severity=severity,
            message=error_str,
            user_message=user_message,
            suggestions=suggestions,
            recovery_actions=recovery_actions,
            can_retry=can_retry,
            fallback_available=fallback_available,
            timestamp=datetime.now()
        )
        
        # Log the error
        self._log_error(error_response, error, context)
        
        return error_response
    
    def _categorize_error(
        self, 
        error: Exception, 
        error_str: str, 
        context: Optional[Dict[str, Any]]
    ) -> ErrorCategory:
        """Categorize the error based on patterns and context."""
        
        # Check for specific error patterns
        for pattern, category in self.error_patterns.items():
            if pattern.lower() in error_str.lower():
                return category
        
        # Check error type
        error_type = type(error).__name__
        
        if error_type in ['ClientError', 'BotoCoreError', 'NoCredentialsError']:
            return ErrorCategory.DATA_ACCESS_ERROR
        elif error_type in ['ConnectionError', 'TimeoutError', 'HTTPError']:
            return ErrorCategory.NETWORK_ERROR
        elif error_type in ['ValueError', 'KeyError', 'AttributeError']:
            return ErrorCategory.CONFIGURATION_ERROR
        elif 'bedrock' in error_str.lower() or 'claude' in error_str.lower():
            return ErrorCategory.AI_ANALYSIS_ERROR
        elif 'athena' in error_str.lower() or 'query' in error_str.lower():
            return ErrorCategory.DATA_ACCESS_ERROR
        elif 'cost' in error_str.lower() or 'limit' in error_str.lower():
            return ErrorCategory.COST_LIMIT_ERROR
        
        return ErrorCategory.UNKNOWN_ERROR
    
    def _assess_severity(
        self, 
        error: Exception, 
        category: ErrorCategory, 
        context: Optional[Dict[str, Any]]
    ) -> ErrorSeverity:
        """Assess the severity of the error."""
        
        # Critical errors that prevent any functionality
        if category in [ErrorCategory.CONFIGURATION_ERROR, ErrorCategory.RESOURCE_ERROR]:
            return ErrorSeverity.CRITICAL
        
        # High severity errors that significantly impact functionality
        if category in [ErrorCategory.DATA_ACCESS_ERROR, ErrorCategory.AI_ANALYSIS_ERROR]:
            return ErrorSeverity.HIGH
        
        # Medium severity errors that partially impact functionality
        if category in [ErrorCategory.COST_LIMIT_ERROR, ErrorCategory.NETWORK_ERROR]:
            return ErrorSeverity.MEDIUM
        
        # Low severity errors that have minimal impact
        return ErrorSeverity.LOW
    
    def _generate_user_message(
        self, 
        category: ErrorCategory, 
        error_str: str, 
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Generate user-friendly error message."""
        
        messages = {
            ErrorCategory.NLP_ERROR: "I had trouble understanding your security question. Could you rephrase it or provide more details?",
            ErrorCategory.DATA_ACCESS_ERROR: "I couldn't access your security data. This might be due to permissions or configuration issues.",
            ErrorCategory.AI_ANALYSIS_ERROR: "The AI analysis service is temporarily unavailable. I can still provide basic data insights.",
            ErrorCategory.COST_LIMIT_ERROR: "This query would exceed your cost limits. Let me suggest some optimizations.",
            ErrorCategory.RESOURCE_ERROR: "System resources are currently limited. Please try again in a few minutes.",
            ErrorCategory.CONFIGURATION_ERROR: "There's a configuration issue that needs to be resolved by an administrator.",
            ErrorCategory.NETWORK_ERROR: "I'm having trouble connecting to AWS services. Please check your network connection.",
            ErrorCategory.UNKNOWN_ERROR: "An unexpected error occurred. I'll try to provide what information I can."
        }
        
        return messages.get(category, "An error occurred while processing your request.")
    
    def _generate_suggestions(
        self, 
        category: ErrorCategory, 
        error_str: str, 
        context: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Generate helpful suggestions for the user."""
        
        suggestions = {
            ErrorCategory.NLP_ERROR: [
                "Try rephrasing your question with more specific terms",
                "Include timeframes (e.g., 'last 24 hours', 'this week')",
                "Specify which systems or data sources you're interested in",
                "Use example questions from the help menu"
            ],
            ErrorCategory.DATA_ACCESS_ERROR: [
                "Verify your AWS credentials are configured correctly",
                "Check that your S3 buckets contain security data",
                "Ensure IAM permissions allow access to Athena and S3",
                "Confirm your data is in the expected format"
            ],
            ErrorCategory.AI_ANALYSIS_ERROR: [
                "Try a simpler question that requires less AI processing",
                "Check if AWS Bedrock is available in your region",
                "Consider using basic data analysis instead of AI insights",
                "Try again in a few minutes as this may be temporary"
            ],
            ErrorCategory.COST_LIMIT_ERROR: [
                "Add more specific time filters to reduce data scanned",
                "Focus on specific systems or data sources",
                "Use data sampling for large datasets",
                "Consider upgrading your usage limits"
            ],
            ErrorCategory.RESOURCE_ERROR: [
                "Wait a few minutes and try again",
                "Try a simpler query that requires fewer resources",
                "Check AWS service status for any ongoing issues",
                "Consider spreading your queries over time"
            ],
            ErrorCategory.CONFIGURATION_ERROR: [
                "Contact your system administrator",
                "Check the system configuration documentation",
                "Verify all required AWS services are properly configured",
                "Review the setup guide for missing steps"
            ],
            ErrorCategory.NETWORK_ERROR: [
                "Check your internet connection",
                "Verify AWS service endpoints are accessible",
                "Try again in a few minutes",
                "Contact your network administrator if issues persist"
            ],
            ErrorCategory.UNKNOWN_ERROR: [
                "Try rephrasing your question",
                "Check if the issue persists with a simpler query",
                "Contact support if the problem continues",
                "Review the system logs for more details"
            ]
        }
        
        return suggestions.get(category, ["Try again later or contact support"])
    
    def _generate_recovery_actions(
        self, 
        category: ErrorCategory, 
        error_str: str, 
        context: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Generate specific recovery actions."""
        
        actions = {
            ErrorCategory.NLP_ERROR: [
                "Retry with rephrased question",
                "Use guided question builder",
                "Select from example questions"
            ],
            ErrorCategory.DATA_ACCESS_ERROR: [
                "Retry with different data sources",
                "Use cached data if available",
                "Switch to demo mode with sample data"
            ],
            ErrorCategory.AI_ANALYSIS_ERROR: [
                "Provide basic data analysis without AI",
                "Use cached analysis results",
                "Retry with simpler analysis request"
            ],
            ErrorCategory.COST_LIMIT_ERROR: [
                "Optimize query automatically",
                "Use data sampling",
                "Provide cost estimate and user confirmation"
            ],
            ErrorCategory.RESOURCE_ERROR: [
                "Queue request for later processing",
                "Use cached results if available",
                "Provide simplified analysis"
            ],
            ErrorCategory.CONFIGURATION_ERROR: [
                "Use default configuration",
                "Switch to demo mode",
                "Provide configuration guidance"
            ],
            ErrorCategory.NETWORK_ERROR: [
                "Retry with exponential backoff",
                "Use cached data if available",
                "Switch to offline mode"
            ],
            ErrorCategory.UNKNOWN_ERROR: [
                "Retry with basic error handling",
                "Provide partial results if available",
                "Log error for investigation"
            ]
        }
        
        return actions.get(category, ["Retry operation"])
    
    def _can_retry(self, category: ErrorCategory, error_type: str) -> bool:
        """Determine if the operation can be retried."""
        
        # Don't retry configuration or critical errors
        if category in [ErrorCategory.CONFIGURATION_ERROR, ErrorCategory.COST_LIMIT_ERROR]:
            return False
        
        # Retry network and resource errors
        if category in [ErrorCategory.NETWORK_ERROR, ErrorCategory.RESOURCE_ERROR]:
            return True
        
        # Retry AI analysis errors (might be temporary)
        if category == ErrorCategory.AI_ANALYSIS_ERROR:
            return True
        
        # Don't retry NLP errors (need user input)
        if category == ErrorCategory.NLP_ERROR:
            return False
        
        return True
    
    def _has_fallback(self, category: ErrorCategory, context: Optional[Dict[str, Any]]) -> bool:
        """Determine if fallback options are available."""
        
        # Most categories have some form of fallback
        fallback_categories = [
            ErrorCategory.AI_ANALYSIS_ERROR,  # Can provide basic analysis
            ErrorCategory.DATA_ACCESS_ERROR,  # Can use cached or demo data
            ErrorCategory.NETWORK_ERROR,      # Can use cached data
            ErrorCategory.RESOURCE_ERROR      # Can provide simplified analysis
        ]
        
        return category in fallback_categories
    
    def _log_error(
        self, 
        error_response: ErrorResponse, 
        original_error: Exception, 
        context: Optional[Dict[str, Any]]
    ) -> None:
        """Log the error with appropriate level based on severity."""
        
        log_message = f"Error {error_response.error_id}: {error_response.message}"
        
        if context:
            log_message += f" | Context: {context}"
        
        if error_response.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message, exc_info=original_error)
        elif error_response.severity == ErrorSeverity.HIGH:
            logger.error(log_message, exc_info=original_error)
        elif error_response.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def _initialize_error_patterns(self) -> Dict[str, ErrorCategory]:
        """Initialize error pattern matching."""
        return {
            "access denied": ErrorCategory.DATA_ACCESS_ERROR,
            "permission denied": ErrorCategory.DATA_ACCESS_ERROR,
            "credentials": ErrorCategory.DATA_ACCESS_ERROR,
            "unauthorized": ErrorCategory.DATA_ACCESS_ERROR,
            "bucket does not exist": ErrorCategory.DATA_ACCESS_ERROR,
            "table not found": ErrorCategory.DATA_ACCESS_ERROR,
            "query failed": ErrorCategory.DATA_ACCESS_ERROR,
            "athena": ErrorCategory.DATA_ACCESS_ERROR,
            "bedrock": ErrorCategory.AI_ANALYSIS_ERROR,
            "claude": ErrorCategory.AI_ANALYSIS_ERROR,
            "model not found": ErrorCategory.AI_ANALYSIS_ERROR,
            "throttling": ErrorCategory.AI_ANALYSIS_ERROR,
            "rate limit": ErrorCategory.AI_ANALYSIS_ERROR,
            "cost limit": ErrorCategory.COST_LIMIT_ERROR,
            "free tier": ErrorCategory.COST_LIMIT_ERROR,
            "quota exceeded": ErrorCategory.COST_LIMIT_ERROR,
            "connection": ErrorCategory.NETWORK_ERROR,
            "timeout": ErrorCategory.NETWORK_ERROR,
            "network": ErrorCategory.NETWORK_ERROR,
            "dns": ErrorCategory.NETWORK_ERROR,
            "ambiguous": ErrorCategory.NLP_ERROR,
            "unclear": ErrorCategory.NLP_ERROR,
            "confidence": ErrorCategory.NLP_ERROR,
            "memory": ErrorCategory.RESOURCE_ERROR,
            "cpu": ErrorCategory.RESOURCE_ERROR,
            "resource": ErrorCategory.RESOURCE_ERROR,
            "configuration": ErrorCategory.CONFIGURATION_ERROR,
            "config": ErrorCategory.CONFIGURATION_ERROR,
            "missing": ErrorCategory.CONFIGURATION_ERROR
        }
    
    def _initialize_recovery_strategies(self) -> Dict[ErrorCategory, Callable]:
        """Initialize recovery strategy functions."""
        # This could be expanded with actual recovery functions
        return {}


class GracefulDegradation:
    """
    Provides graceful degradation strategies when components fail.
    """
    
    @staticmethod
    def provide_basic_data_analysis(query_results) -> Dict[str, Any]:
        """Provide basic data analysis when AI analysis fails."""
        if not query_results or not hasattr(query_results, 'data'):
            return {
                "analysis_type": "basic",
                "summary": "No data available for analysis",
                "recommendations": ["Ensure data sources are properly configured"]
            }
        
        # Basic statistical analysis
        row_count = getattr(query_results, 'row_count', 0)
        data_size = getattr(query_results, 'data_scanned_gb', 0.0)
        
        return {
            "analysis_type": "basic",
            "summary": f"Analyzed {row_count} security events from {data_size:.2f} GB of data",
            "statistics": {
                "total_events": row_count,
                "data_processed_gb": data_size,
                "analysis_time": getattr(query_results, 'execution_time_ms', 0)
            },
            "recommendations": [
                "Review the raw data for patterns",
                "Consider manual analysis of high-volume events",
                "Try the AI analysis again when services are available"
            ]
        }
    
    @staticmethod
    def provide_cached_insights(cache_key: str) -> Optional[Dict[str, Any]]:
        """Provide cached insights when real-time analysis fails."""
        # This would integrate with an actual cache system
        return {
            "analysis_type": "cached",
            "summary": "Showing cached analysis results",
            "note": "These results may not reflect the most recent data",
            "recommendations": ["Retry for updated analysis when services are available"]
        }
    
    @staticmethod
    def provide_demo_analysis() -> Dict[str, Any]:
        """Provide demo analysis when no data is available."""
        return {
            "analysis_type": "demo",
            "summary": "Demo security analysis showing system capabilities",
            "demo_threats": [
                {
                    "type": "Suspicious Login",
                    "severity": "Medium",
                    "description": "Multiple failed login attempts detected"
                },
                {
                    "type": "Unusual Network Traffic",
                    "severity": "Low", 
                    "description": "Increased data transfer during off-hours"
                }
            ],
            "recommendations": [
                "Configure your security data sources",
                "Upload sample security logs",
                "Review the setup documentation"
            ],
            "note": "This is demonstration data. Configure real data sources for actual analysis."
        }