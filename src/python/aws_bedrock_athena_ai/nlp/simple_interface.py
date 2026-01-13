"""
Simple Natural Language Interface for AI Security Analyst.

This module provides a simplified interface for processing natural language
security questions, focusing on intent recognition and context extraction.
"""

import time
from typing import Optional, List
import logging

from aws_bedrock_athena_ai.nlp.intent_recognizer import SecurityIntentRecognizer
from aws_bedrock_athena_ai.nlp.context_extractor import SecurityContextExtractor
from aws_bedrock_athena_ai.nlp.models import NLPResponse, SecurityIntent, QueryContext, SecurityIntentType

logger = logging.getLogger(__name__)


class SimpleNaturalLanguageInterface:
    """
    Simplified interface for processing natural language security questions.
    
    This class provides basic intent recognition and context extraction
    for security questions without complex disambiguation.
    """
    
    def __init__(self):
        self.intent_recognizer = SecurityIntentRecognizer()
        self.context_extractor = SecurityContextExtractor()
        
        logger.info("Simple Natural Language Interface initialized")
    
    def parse_security_question(
        self, 
        question: str,
        conversation_history: Optional[List[str]] = None
    ) -> NLPResponse:
        """
        Parse a security question and extract intent and context.
        
        Args:
            question: The security question to parse
            conversation_history: Previous questions in the conversation
            
        Returns:
            NLPResponse with intent and context
        """
        start_time = time.time()
        
        try:
            # Step 1: Recognize security intent
            logger.debug(f"Recognizing intent for question: {question}")
            intent = self.intent_recognizer.recognize_intent(question)
            
            # Step 2: Extract context
            logger.debug(f"Extracting context for intent: {intent.intent_type}")
            context = self.context_extractor.extract_context(
                question, intent, conversation_history
            )
            
            # Create response
            response = NLPResponse(
                intent=intent,
                context=context,
                disambiguation=None
            )
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000
            response.processing_time_ms = processing_time
            
            logger.info(
                f"Processed question successfully: intent={intent.intent_type}, "
                f"confidence={intent.confidence:.2f}, "
                f"processing_time={processing_time:.1f}ms"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing security question: {e}")
            
            # Return a fallback response
            fallback_intent = SecurityIntent(
                intent_type=SecurityIntentType.UNKNOWN,
                confidence=0.0,
                clarification_needed=True,
                clarification_questions=[
                    "I encountered an error processing your question. Could you rephrase it?"
                ],
                original_question=question
            )
            
            fallback_context = QueryContext()
            if conversation_history:
                fallback_context.conversation_history = conversation_history
            
            return NLPResponse(
                intent=fallback_intent,
                context=fallback_context,
                processing_time_ms=(time.time() - start_time) * 1000
            )
    
    def get_supported_intents(self) -> List[str]:
        """Get a list of supported security intent types."""
        return [intent.value for intent in SecurityIntentType if intent != SecurityIntentType.UNKNOWN]
    
    def get_example_questions(self) -> List[str]:
        """Get example questions that demonstrate the system's capabilities."""
        return [
            "Are we being attacked right now?",
            "Show me security threats from last week",
            "What are our biggest security risks?",
            "Check for compliance violations on web servers",
            "Investigate the security incident from yesterday",
            "Find suspicious login attempts from the past 24 hours",
            "Analyze malware activity on endpoints",
            "Review user access permissions",
            "Detect anomalies in network traffic",
            "Assess vulnerability status of our systems"
        ]