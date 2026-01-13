"""
Main FastAPI application for AI Security Analyst API.
"""

import uuid
import logging
from typing import Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from aws_bedrock_athena_ai.api.models import (
    SecurityQuestionRequest, SecurityQuestionResponse, ClarificationRequest,
    ErrorResponse, HealthResponse, RateLimitInfo, ApiKeyRequest, ApiKeyResponse
)
from aws_bedrock_athena_ai.api.auth import get_current_user, require_permission, auth_manager, DEMO_KEY
from aws_bedrock_athena_ai.nlp.natural_language_interface import NaturalLanguageInterface
from aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective
from aws_bedrock_athena_ai.reasoning_engine.expert_reasoning_engine import ExpertReasoningEngine
from aws_bedrock_athena_ai.insights.instant_insights_generator import InstantInsightsGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AI Security Analyst API",
    description="REST API for natural language security analysis using AWS Bedrock and Athena",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount static files
from pathlib import Path
static_dir = Path(__file__).parent.parent / "web" / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
nlp_interface = NaturalLanguageInterface()
data_detective = SmartDataDetective()
reasoning_engine = ExpertReasoningEngine()
insights_generator = InstantInsightsGenerator()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error_code="INTERNAL_ERROR",
            error_message="An internal error occurred",
            details={"exception": str(exc)}
        ).dict()
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        components={
            "nlp": "healthy",
            "data_detective": "healthy", 
            "reasoning_engine": "healthy",
            "insights_generator": "healthy"
        }
    )


@app.get("/")
async def root():
    """Serve the web interface."""
    static_dir = Path(__file__).parent.parent / "web" / "static"
    return FileResponse(str(static_dir / "index.html"))


@app.get("/api")
async def api_info():
    """API information endpoint."""
    return {
        "message": "AI Security Analyst API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "demo_api_key": DEMO_KEY["api_key"],
        "example_questions": nlp_interface.get_example_questions()
    }


@app.post("/api/v1/security/question", response_model=SecurityQuestionResponse)
async def ask_security_question(
    request: SecurityQuestionRequest,
    user_data: Dict = Depends(require_permission("query"))
):
    """
    Process a natural language security question.
    
    This endpoint accepts security questions in plain English and returns
    expert-level analysis with recommendations and visualizations.
    """
    try:
        start_time = datetime.utcnow()
        
        # Generate conversation ID if not provided
        conversation_id = request.conversation_id or str(uuid.uuid4())
        
        logger.info(f"Processing security question: {request.question[:100]}...")
        
        # Step 1: Parse the natural language question
        nlp_response = nlp_interface.parse_security_question(
            question=request.question,
            conversation_history=request.conversation_history,
            conversation_id=conversation_id
        )
        
        # If clarification is needed, return early
        if nlp_response.needs_clarification:
            return SecurityQuestionResponse(
                success=True,
                conversation_id=conversation_id,
                needs_clarification=True,
                clarification_questions=nlp_response.intent.clarification_questions,
                processing_time_ms=nlp_response.processing_time_ms,
                confidence_score=nlp_response.intent.confidence
            )
        
        # Step 2: Query data using Smart Data Detective
        logger.info("Querying security data...")
        query_results = data_detective.execute_security_query(
            intent=nlp_response.intent,
            context=nlp_response.context
        )
        
        # Step 3: Analyze with Expert Reasoning Engine
        logger.info("Performing expert analysis...")
        threat_analysis = reasoning_engine.analyze_security_patterns(query_results)
        
        # Step 4: Generate insights
        logger.info("Generating insights...")
        executive_report = insights_generator.generate_executive_summary(threat_analysis)
        technical_report = insights_generator.generate_technical_details(threat_analysis)
        visualizations = insights_generator.generate_visualizations(query_results)
        action_plan = insights_generator.build_action_plan(threat_analysis.recommendations)
        
        # Calculate total processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Format response
        return SecurityQuestionResponse(
            success=True,
            conversation_id=conversation_id,
            needs_clarification=False,
            executive_summary=executive_report.summary,
            technical_details={
                "threats_found": len(threat_analysis.threats_identified),
                "risk_score": threat_analysis.risk_score,
                "analysis_details": technical_report.detailed_findings
            },
            recommendations=[
                {
                    "id": rec.recommendation_id,
                    "priority": rec.priority,
                    "description": rec.description,
                    "implementation_steps": rec.implementation_steps,
                    "business_impact": rec.business_impact
                }
                for rec in threat_analysis.recommendations
            ],
            visualizations=[
                {
                    "type": viz.visualization_type,
                    "title": viz.title,
                    "data": viz.data,
                    "config": viz.config
                }
                for viz in visualizations
            ],
            action_plan={
                "plan_id": action_plan.plan_id,
                "priority_actions": [
                    {
                        "action": action.action_description,
                        "priority": action.priority_level,
                        "timeline": action.estimated_timeline,
                        "effort": action.effort_estimate
                    }
                    for action in action_plan.priority_actions
                ],
                "total_estimated_effort": action_plan.total_estimated_effort
            },
            processing_time_ms=processing_time,
            confidence_score=threat_analysis.confidence_level
        )
        
    except Exception as e:
        logger.error(f"Error processing security question: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error processing security question: {str(e)}"
        )


@app.post("/api/v1/security/clarification", response_model=SecurityQuestionResponse)
async def handle_clarification(
    request: ClarificationRequest,
    user_data: Dict = Depends(require_permission("query"))
):
    """
    Handle clarification responses for ambiguous questions.
    """
    try:
        logger.info(f"Handling clarification for conversation {request.conversation_id}")
        
        # Process clarification response
        nlp_response = nlp_interface.handle_clarification_response(
            original_question=request.original_question,
            clarification_response=request.clarification_response,
            conversation_id=request.conversation_id
        )
        
        if not nlp_response:
            # Still need more clarification
            return SecurityQuestionResponse(
                success=True,
                conversation_id=request.conversation_id,
                needs_clarification=True,
                clarification_questions=["Could you provide more specific details?"],
                processing_time_ms=0.0,
                confidence_score=0.0
            )
        
        # If we have a clear understanding now, process normally
        # (This would follow the same logic as ask_security_question)
        return SecurityQuestionResponse(
            success=True,
            conversation_id=request.conversation_id,
            needs_clarification=False,
            executive_summary="Clarification processed successfully",
            processing_time_ms=nlp_response.processing_time_ms,
            confidence_score=nlp_response.intent.confidence
        )
        
    except Exception as e:
        logger.error(f"Error handling clarification: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error handling clarification: {str(e)}"
        )


@app.get("/api/v1/security/examples")
async def get_example_questions(
    user_data: Dict = Depends(get_current_user)
):
    """Get example security questions."""
    return {
        "examples": nlp_interface.get_example_questions(),
        "supported_intents": nlp_interface.get_supported_intents()
    }


@app.get("/api/v1/auth/rate-limit", response_model=RateLimitInfo)
async def get_rate_limit_info(
    user_data: Dict = Depends(get_current_user)
):
    """Get current rate limit information."""
    # Get the API key from the current request context
    # This is a simplified approach - in production, you'd track this properly
    import hashlib
    key_hash = "demo_hash"  # Simplified for demo
    
    rate_info = auth_manager.get_rate_limit_info(key_hash)
    return RateLimitInfo(**rate_info)


@app.post("/api/v1/auth/api-key", response_model=ApiKeyResponse)
async def create_api_key(
    request: ApiKeyRequest,
    user_data: Dict = Depends(require_permission("admin"))
):
    """Create a new API key (admin only)."""
    try:
        key_data = auth_manager.generate_api_key(
            name=request.name,
            permissions=request.permissions
        )
        
        return ApiKeyResponse(
            api_key=key_data["api_key"],
            key_id=key_data["key_id"],
            name=key_data["name"],
            permissions=key_data["permissions"]
        )
        
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error creating API key: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)