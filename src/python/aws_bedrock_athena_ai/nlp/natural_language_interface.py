"""
Natural Language Interface for AI Security Analyst.

This module provides the main interface for processing natural language
security questions, combining intent recognition, context extraction,
and query disambiguation.
"""

import time
from typing import Optional, List
import logging

from aws_bedrock_athena_ai.nlp.intent_recognizer import SecurityIntentRecognizer
from aws_bedrock_athena_ai.nlp.context_extractor import SecurityContextExtractor
from aws_bedrock_athena_ai.nlp.query_disambiguator import QueryDisambiguator
from aws_bedrock_athena_ai.nlp.models import NLPResponse, SecurityIntent, QueryContext, SecurityIntentType

logger = logging.getLogger(__name__)


class NaturalLanguageInterface:
    """
    Main interface for processing natural language security questions.
    
    This class coordinates intent recognition, context extraction, and
    query disambiguation to provide a complete natural language understanding
    system for security questions.
    """
    
    def __init__(self):
        self.intent_recognizer = SecurityIntentRecognizer()
        self.context_extractor = SecurityContextExtractor()
        self.query_disambiguator = QueryDisambiguator()
        
        logger.info("Natural Language Interface initialized")
    
    def parse_security_question(
        self, 
        question: str,
        conversation_history: Optional[List[str]] = None,
        conversation_id: Optional[str] = None
    ) -> NLPResponse:
        """
        Parse a security question and extract intent and context.
        
        Args:
            question: The security question to parse
            conversation_history: Previous questions in the conversation
            conversation_id: ID for tracking multi-turn conversations
            
        Returns:
            NLPResponse with intent, context, and disambiguation if needed
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
            
            # Step 3: Check if disambiguation is needed
            logger.debug(f"Checking disambiguation needs (confidence: {intent.confidence})")
            response = self.query_disambiguator.disambiguate_query(
                question, intent, context, conversation_id
            )
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000
            response.processing_time_ms = processing_time
            
            logger.info(
                f"Processed question successfully: intent={intent.intent_type}, "
                f"confidence={intent.confidence:.2f}, "
                f"needs_clarification={response.needs_clarification}, "
                f"processing_time={processing_time:.1f}ms"
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing security question: {e}")
            
            # Return a fallback response
            fallback_intent = SecurityIntent(
                intent_type=intent.intent_type if 'intent' in locals() else SecurityIntentType.UNKNOWN,
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
    
    def handle_clarification_response(
        self,
        original_question: str,
        clarification_response: str,
        conversation_id: str
    ) -> Optional[NLPResponse]:
        """
        Handle a user's response to clarification questions.
        
        Args:
            original_question: The original ambiguous question
            clarification_response: User's response to clarification
            conversation_id: ID for tracking the conversation
            
        Returns:
            New NLPResponse with updated understanding, or None if more clarification needed
        """
        try:
            # Let the disambiguator handle the clarification
            reformulated_question = self.query_disambiguator.handle_clarification_response(
                original_question, clarification_response, conversation_id
            )
            
            if reformulated_question:
                # Re-process the reformulated question
                logger.info(f"Reformulated question: {reformulated_question}")
                return self.parse_security_question(
                    reformulated_question, 
                    conversation_id=conversation_id
                )
            else:
                logger.debug("More clarification needed")
                return None
                
        except Exception as e:
            logger.error(f"Error handling clarification response: {e}")
            return None
    
    def get_conversation_context(self, conversation_id: str) -> Optional[dict]:
        """Get the conversation context for a given conversation ID."""
        return self.query_disambiguator.get_conversation_context(conversation_id)
    
    def clear_conversation_context(self, conversation_id: str) -> None:
        """Clear the conversation context for a given conversation ID."""
        self.query_disambiguator.clear_conversation_context(conversation_id)
    
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