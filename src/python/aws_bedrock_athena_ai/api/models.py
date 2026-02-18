"""
API models for request/response schemas.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class SecurityQuestionRequest(BaseModel):
    """Request model for security questions."""
    question: str = Field(..., min_length=1, max_length=1000, description="Security question in natural language")
    conversation_id: Optional[str] = Field(None, description="ID for multi-turn conversations")
    conversation_history: Optional[List[str]] = Field(None, description="Previous questions in conversation")
    user_role: Optional[str] = Field("analyst", description="User role for context (analyst, executive, admin)")


class ClarificationRequest(BaseModel):
    """Request model for clarification responses."""
    original_question: str = Field(..., description="Original ambiguous question")
    clarification_response: str = Field(..., description="User's response to clarification")
    conversation_id: str = Field(..., description="Conversation ID")


class SecurityQuestionResponse(BaseModel):
    """Response model for security questions."""
    success: bool = Field(..., description="Whether the request was successful")
    conversation_id: str = Field(..., description="Conversation ID for tracking")
    needs_clarification: bool = Field(..., description="Whether clarification is needed")
    clarification_questions: Optional[List[str]] = Field(None, description="Questions for clarification")
    
    # Analysis results (when available)
    executive_summary: Optional[str] = Field(None, description="Executive summary of findings")
    technical_details: Optional[Dict[str, Any]] = Field(None, description="Technical analysis details")
    recommendations: Optional[List[Dict[str, Any]]] = Field(None, description="Security recommendations")
    visualizations: Optional[List[Dict[str, Any]]] = Field(None, description="Data visualizations")
    action_plan: Optional[Dict[str, Any]] = Field(None, description="Prioritized action plan")
    
    # Metadata
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    confidence_score: float = Field(..., description="Confidence in the analysis")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = Field(False, description="Always false for errors")
    error_code: str = Field(..., description="Error code")
    error_message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    components: Dict[str, str] = Field(..., description="Component health status")


class RateLimitInfo(BaseModel):
    """Rate limit information."""
    requests_remaining: int = Field(..., description="Requests remaining in current window")
    reset_time: datetime = Field(..., description="When the rate limit resets")
    limit_per_hour: int = Field(..., description="Total requests allowed per hour")


class ApiKeyRequest(BaseModel):
    """Request model for API key operations."""
    name: str = Field(..., description="Name for the API key")
    permissions: List[str] = Field(default=["query"], description="Permissions for the API key")


class ApiKeyResponse(BaseModel):
    """Response model for API key creation."""
    api_key: str = Field(..., description="Generated API key")
    key_id: str = Field(..., description="Unique key identifier")
    name: str = Field(..., description="Key name")
    permissions: List[str] = Field(..., description="Key permissions")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")