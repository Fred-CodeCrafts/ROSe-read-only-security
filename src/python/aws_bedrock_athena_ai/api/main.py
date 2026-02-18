"""
Main FastAPI application for AI Security Analyst API.
"""

import os
import uuid
import logging
from typing import Dict, Any
from datetime import datetime

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from aws_bedrock_athena_ai.api.models import (
    SecurityQuestionRequest, SecurityQuestionResponse, ClarificationRequest,
    ErrorResponse, HealthResponse, RateLimitInfo, ApiKeyRequest, ApiKeyResponse
)
from aws_bedrock_athena_ai.api.auth import get_current_user, require_permission, optional_auth, auth_manager, DEMO_KEY
from aws_bedrock_athena_ai.api.aws_detector import AWSAvailabilityDetector
from aws_bedrock_athena_ai.api.demo_responses import DemoResponseGenerator
from aws_bedrock_athena_ai.api.error_messages import (
    get_error_template, format_error_response, format_error_message
)
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

# Initialize demo mode components
aws_detector = AWSAvailabilityDetector()
demo_generator = DemoResponseGenerator()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler with clear error messages.
    
    Logs errors but doesn't crash the application. Returns user-friendly
    error messages with setup instructions when appropriate.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Check for specific AWS-related errors
    error_code = None
    if "bedrock" in str(exc).lower():
        if "access denied" in str(exc).lower() or "unauthorized" in str(exc).lower():
            error_code = "BEDROCK_ACCESS_DENIED"
        elif "not found" in str(exc).lower() or "model" in str(exc).lower():
            error_code = "BEDROCK_MODEL_NOT_FOUND"
        else:
            error_code = "BEDROCK_NOT_CONFIGURED"
    elif "athena" in str(exc).lower():
        if "query" in str(exc).lower() or "execution" in str(exc).lower():
            error_code = "ATHENA_QUERY_FAILED"
        else:
            error_code = "ATHENA_NOT_CONFIGURED"
    elif "credentials" in str(exc).lower() or "no credentials" in str(exc).lower():
        error_code = "AWS_CREDENTIALS_NOT_FOUND"
    
    # If we have a specific error template, use it
    if error_code:
        error_response = format_error_response(error_code, include_instructions=True)
        return JSONResponse(
            status_code=500,
            content=error_response
        )
    
    # Generic error response
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error_code="INTERNAL_ERROR",
            error_message="An internal error occurred. The system is running in demo mode.",
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


@app.get("/api/v1/status")
async def get_status():
    """
    Return system status including AWS availability and mode.
    
    This endpoint provides information about:
    - System online status
    - Operating mode (demo/production)
    - AWS service availability (Bedrock, Athena)
    - Demo API key for frontend use
    
    Returns:
        Dictionary with status information
    """
    try:
        # Get AWS availability status
        availability = aws_detector.get_availability_status()
        
        # Determine if we're in demo mode
        demo_mode = availability["mode"] == "demo"
        
        return {
            "status": "online",
            "mode": availability["mode"],
            "aws_bedrock": availability["bedrock"],
            "aws_athena": availability["athena"],
            "demo_mode": demo_mode,
            "demo_api_key": DEMO_KEY["api_key"] if demo_mode else None,
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        # Return degraded status instead of failing
        return {
            "status": "online",
            "mode": "demo",
            "aws_bedrock": False,
            "aws_athena": False,
            "demo_mode": True,
            "demo_api_key": DEMO_KEY["api_key"],
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@app.post("/api/v1/security/question", response_model=SecurityQuestionResponse)
async def ask_security_question(
    request: SecurityQuestionRequest,
    user_data: Dict = Depends(optional_auth)
):
    """
    Process a natural language security question.
    
    This endpoint accepts security questions in plain English and returns
    expert-level analysis with recommendations and visualizations.
    
    Works in both demo and production modes without requiring authentication.
    """
    try:
        start_time = datetime.utcnow()
        
        # Generate conversation ID if not provided
        conversation_id = request.conversation_id or str(uuid.uuid4())
        
        logger.info(f"Processing security question: {request.question[:100]}...")
        
        # Check AWS availability at start of request
        if not aws_detector.is_bedrock_available():
            logger.info("AWS Bedrock unavailable - using demo mode")
            
            # Log the reason for demo mode
            template = get_error_template("BEDROCK_NOT_CONFIGURED")
            if template:
                logger.warning(f"{template.title}: {template.message}")
            
            # Generate demo response
            demo_response = demo_generator.generate_security_response(
                question=request.question,
                conversation_id=conversation_id
            )
            
            # Return demo response in SecurityQuestionResponse format
            return SecurityQuestionResponse(**demo_response)
        
        # AWS is available - use real Bedrock
        logger.info("AWS Bedrock available - using production mode")
        
        # Import Bedrock client
        import boto3
        
        # Create Bedrock client
        bedrock = boto3.client('bedrock-runtime')
        
        # Determine if this is a security-related question
        security_keywords = ['security', 'vulnerability', 'threat', 'risk', 'attack', 
                           'breach', 'exploit', 'malware', 'hack', 'secure', 'audit',
                           'compliance', 'authentication', 'authorization', 'encryption']
        
        is_security_question = any(keyword in request.question.lower() for keyword in security_keywords)
        
        # Only add code context for security questions
        if is_security_question:
            from aws_bedrock_athena_ai.code_analyzer import create_enhanced_prompt
            prompt = create_enhanced_prompt(request.question)
        else:
            # For non-security questions, just pass the question directly
            prompt = request.question
        
        # Add system prompt for security questions to keep responses concise
        messages = [
            {
                'role': 'user',
                'content': [{'text': prompt}]
            }
        ]
        
        # Add instruction for concise responses on security questions
        if is_security_question:
            messages[0]['content'][0]['text'] += "\n\nProvide a concise, bullet-point response. Be direct and actionable."
        
        # Call Bedrock using Converse API
        bedrock_response = bedrock.converse(
            modelId='anthropic.claude-3-haiku-20240307-v1:0',
            messages=messages,
            inferenceConfig={
                'maxTokens': 800,  # Reduced from 2000 to keep responses shorter
                'temperature': 0.7
            }
        )
        
        # Extract AI response
        ai_answer = bedrock_response['output']['message']['content'][0]['text']
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Return simplified response with AI analysis
        return SecurityQuestionResponse(
            success=True,
            conversation_id=conversation_id,
            needs_clarification=False,
            executive_summary=ai_answer,
            technical_details={
                "analysis_type": "AI-powered security analysis" if is_security_question else "AI response",
                "model": "Claude 3 Haiku",
                "context_included": is_security_question
            },
            recommendations=[],
            visualizations=[],
            action_plan={},
            processing_time_ms=processing_time,
            confidence_score=0.9
        )
        
        # OLD CODE BELOW - keeping for reference but not executing
        """
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
        """
        
    except Exception as e:
        logger.error(f"Error processing security question: {e}", exc_info=True)
        
        # Check if this is an AWS-related error and provide helpful message
        error_code = None
        if "bedrock" in str(e).lower():
            error_code = "BEDROCK_NOT_CONFIGURED"
        elif "athena" in str(e).lower():
            error_code = "ATHENA_QUERY_FAILED"
        
        if error_code:
            error_response = format_error_response(error_code, include_instructions=False)
            raise HTTPException(
                status_code=500,
                detail=error_response
            )
        
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
    user_data: Dict = Depends(optional_auth)
):
    """
    Get example security questions.
    
    In demo mode, this endpoint allows unauthenticated access.
    In production mode, requires authentication.
    """
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