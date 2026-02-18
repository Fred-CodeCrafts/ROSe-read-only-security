"""
Query Disambiguation and Clarification System.

This module handles ambiguous security questions by providing clarification
prompts and supporting multi-turn conversations for complex investigations.
"""

from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
import logging
from enum import Enum

from .models import (
    SecurityIntent, SecurityIntentType, QueryContext, DisambiguationRequest,
    NLPResponse, SecurityEntity, EntityType
)

logger = logging.getLogger(__name__)


class ClarificationType(Enum):
    """Types of clarification that might be needed."""
    INTENT_AMBIGUOUS = "intent_ambiguous"
    MISSING_TIMEFRAME = "missing_timeframe"
    MISSING_SYSTEM = "missing_system"
    MISSING_CONTEXT = "missing_context"
    MULTIPLE_INTENTS = "multiple_intents"
    VAGUE_QUESTION = "vague_question"


@dataclass
class ClarificationStrategy:
    """Strategy for handling a specific type of clarification."""
    clarification_type: ClarificationType
    questions: List[str]
    suggested_reformulations: List[str]
    priority: int = 1  # Higher number = higher priority


class QueryDisambiguator:
    """
    Handles ambiguous security questions and provides clarification.
    
    This class analyzes security questions that are unclear or ambiguous
    and generates appropriate clarification questions to help users
    provide more specific information.
    """
    
    def __init__(self):
        self.clarification_strategies = self._initialize_clarification_strategies()
        self.conversation_context = {}  # Store context for multi-turn conversations
    
    def _initialize_clarification_strategies(self) -> Dict[ClarificationType, ClarificationStrategy]:
        """Initialize strategies for different types of clarification."""
        return {
            ClarificationType.INTENT_AMBIGUOUS: ClarificationStrategy(
                clarification_type=ClarificationType.INTENT_AMBIGUOUS,
                questions=[
                    "I'm not sure what type of security analysis you're looking for. Could you clarify?",
                    "Are you asking about threat detection, compliance checking, or something else?",
                    "What specific security concern would you like me to investigate?"
                ],
                suggested_reformulations=[
                    "Are we under attack right now?",
                    "Show me compliance violations from last week",
                    "What are our biggest security risks?",
                    "Investigate the security incident from yesterday"
                ],
                priority=3
            ),
            
            ClarificationType.MULTIPLE_INTENTS: ClarificationStrategy(
                clarification_type=ClarificationType.MULTIPLE_INTENTS,
                questions=[
                    "Your question could relate to multiple security areas. Which would you like me to focus on?",
                    "I see this could be about {intent1} or {intent2}. Which is more important right now?",
                    "Should I prioritize {primary_intent} or also include {secondary_intent}?"
                ],
                suggested_reformulations=[],
                priority=2
            ),
            
            ClarificationType.MISSING_TIMEFRAME: ClarificationStrategy(
                clarification_type=ClarificationType.MISSING_TIMEFRAME,
                questions=[
                    "What time period should I analyze?",
                    "Are you interested in recent activity or a specific time range?",
                    "Should I look at the last 24 hours, week, or a different timeframe?"
                ],
                suggested_reformulations=[
                    "Show me threats from the last 24 hours",
                    "Analyze security events from last week",
                    "Check for incidents from yesterday"
                ],
                priority=2
            ),
            
            ClarificationType.MISSING_SYSTEM: ClarificationStrategy(
                clarification_type=ClarificationType.MISSING_SYSTEM,
                questions=[
                    "Which systems or applications should I focus on?",
                    "Are you asking about all systems or specific ones?",
                    "Should I analyze web servers, databases, endpoints, or all infrastructure?"
                ],
                suggested_reformulations=[
                    "Check web servers for threats",
                    "Analyze database security",
                    "Review endpoint security status"
                ],
                priority=2
            ),
            
            ClarificationType.MISSING_CONTEXT: ClarificationStrategy(
                clarification_type=ClarificationType.MISSING_CONTEXT,
                questions=[
                    "Could you provide more details about what you're concerned about?",
                    "What specific indicators or symptoms have you noticed?",
                    "Is this related to a particular incident or general monitoring?"
                ],
                suggested_reformulations=[
                    "Investigate suspicious login attempts",
                    "Check for malware on user workstations",
                    "Analyze unusual network traffic patterns"
                ],
                priority=1
            ),
            
            ClarificationType.VAGUE_QUESTION: ClarificationStrategy(
                clarification_type=ClarificationType.VAGUE_QUESTION,
                questions=[
                    "Your question is quite broad. Could you be more specific?",
                    "What particular aspect of security are you most concerned about?",
                    "Are you looking for an overview or investigating something specific?"
                ],
                suggested_reformulations=[
                    "What are our top 5 security risks?",
                    "Show me critical security alerts",
                    "Are there any active security incidents?"
                ],
                priority=1
            )
        }
    
    def disambiguate_query(
        self, 
        question: str, 
        intent: SecurityIntent, 
        context: QueryContext,
        conversation_id: Optional[str] = None
    ) -> NLPResponse:
        """
        Disambiguate an ambiguous security query.
        
        Args:
            question: The original security question
            intent: The recognized (possibly ambiguous) intent
            context: The extracted context
            conversation_id: ID for tracking multi-turn conversations
            
        Returns:
            NLPResponse with disambiguation information if needed
        """
        # Analyze what clarification is needed
        clarification_needs = self._analyze_clarification_needs(question, intent, context)
        
        if not clarification_needs:
            # No clarification needed
            return NLPResponse(
                intent=intent,
                context=context,
                disambiguation=None
            )
        
        # Generate disambiguation request
        disambiguation = self._generate_disambiguation_request(
            question, intent, clarification_needs, conversation_id
        )
        
        return NLPResponse(
            intent=intent,
            context=context,
            disambiguation=disambiguation
        )
    
    def _analyze_clarification_needs(
        self, 
        question: str, 
        intent: SecurityIntent, 
        context: QueryContext
    ) -> List[ClarificationType]:
        """Analyze what types of clarification are needed."""
        needs = []
        
        # Check if intent is ambiguous or unknown
        if intent.intent_type == SecurityIntentType.UNKNOWN or intent.confidence < 0.3:
            needs.append(ClarificationType.INTENT_AMBIGUOUS)
        
        # Check for multiple possible intents (if confidence is low but not unknown)
        if (intent.intent_type != SecurityIntentType.UNKNOWN and 
            intent.confidence < 0.6 and intent.confidence > 0.2):
            needs.append(ClarificationType.MULTIPLE_INTENTS)
        
        # Check for missing timeframe
        if not context.timeframe and self._requires_timeframe(intent.intent_type):
            needs.append(ClarificationType.MISSING_TIMEFRAME)
        
        # Check for missing system context
        if not context.systems and self._requires_system_context(intent.intent_type):
            needs.append(ClarificationType.MISSING_SYSTEM)
        
        # Check for vague questions
        if self._is_vague_question(question):
            needs.append(ClarificationType.VAGUE_QUESTION)
        
        # Check for missing context based on intent type
        if self._needs_additional_context(question, intent, context):
            needs.append(ClarificationType.MISSING_CONTEXT)
        
        return needs
    
    def _requires_timeframe(self, intent_type: SecurityIntentType) -> bool:
        """Check if an intent type typically requires a timeframe."""
        timeframe_required_intents = {
            SecurityIntentType.THREAT_HUNTING,
            SecurityIntentType.INCIDENT_INVESTIGATION,
            SecurityIntentType.ANOMALY_DETECTION,
            SecurityIntentType.ACCESS_REVIEW
        }
        return intent_type in timeframe_required_intents
    
    def _requires_system_context(self, intent_type: SecurityIntentType) -> bool:
        """Check if an intent type typically requires system context."""
        system_required_intents = {
            SecurityIntentType.VULNERABILITY_SCAN,
            SecurityIntentType.COMPLIANCE_CHECK,
            SecurityIntentType.RISK_ASSESSMENT
        }
        return intent_type in system_required_intents
    
    def _is_vague_question(self, question: str) -> bool:
        """Check if a question is too vague."""
        vague_indicators = [
            "security", "safe", "secure", "protected", "status", "check",
            "how are we", "what about", "tell me about"
        ]
        
        question_lower = question.lower()
        word_count = len(question.split())
        
        # Very short questions with vague terms
        if word_count <= 4 and any(indicator in question_lower for indicator in vague_indicators):
            return True
        
        # Questions that are just single words or very generic
        if word_count <= 2:
            return True
        
        return False
    
    def _needs_additional_context(
        self, 
        question: str, 
        intent: SecurityIntent, 
        context: QueryContext
    ) -> bool:
        """Check if additional context is needed based on the specific intent."""
        question_lower = question.lower()
        
        # Threat hunting needs specific indicators
        if (intent.intent_type == SecurityIntentType.THREAT_HUNTING and 
            not context.threat_types and not context.ip_addresses and 
            not any(word in question_lower for word in ["suspicious", "malicious", "attack", "breach"])):
            return True
        
        # Incident investigation needs incident details
        if (intent.intent_type == SecurityIntentType.INCIDENT_INVESTIGATION and
            not any(word in question_lower for word in ["incident", "alert", "breach", "compromise"])):
            return True
        
        return False
    
    def _generate_disambiguation_request(
        self, 
        question: str, 
        intent: SecurityIntent,
        clarification_needs: List[ClarificationType],
        conversation_id: Optional[str]
    ) -> DisambiguationRequest:
        """Generate a disambiguation request with appropriate questions."""
        
        # Sort clarification needs by priority
        sorted_needs = sorted(
            clarification_needs,
            key=lambda x: self.clarification_strategies[x].priority,
            reverse=True
        )
        
        # Generate clarification questions (limit to top 2 priorities)
        clarification_questions = []
        suggested_reformulations = []
        
        for need in sorted_needs[:2]:  # Limit to top 2 priorities
            strategy = self.clarification_strategies[need]
            
            if need == ClarificationType.MULTIPLE_INTENTS:
                # Special handling for multiple intents
                questions = self._generate_multiple_intent_questions(intent)
            else:
                questions = strategy.questions[:1]  # Take first question from strategy
            
            clarification_questions.extend(questions)
            suggested_reformulations.extend(strategy.suggested_reformulations[:2])
        
        # Generate possible intents for disambiguation
        possible_intents = self._generate_possible_intents(question, intent)
        
        return DisambiguationRequest(
            original_question=question,
            possible_intents=possible_intents,
            clarification_questions=clarification_questions,
            suggested_reformulations=suggested_reformulations
        )
    
    def _generate_multiple_intent_questions(self, intent: SecurityIntent) -> List[str]:
        """Generate questions for multiple possible intents."""
        # This would typically involve analyzing multiple possible intents
        # For now, return a generic question
        return [
            "I see multiple possible interpretations of your question. "
            "Could you clarify which aspect is most important to you?"
        ]
    
    def _generate_possible_intents(
        self, 
        question: str, 
        primary_intent: SecurityIntent
    ) -> List[SecurityIntent]:
        """Generate a list of possible intents for disambiguation."""
        possible_intents = [primary_intent]
        
        # This is a simplified implementation
        # In a real system, you might re-run intent recognition with different parameters
        # or use multiple models to get alternative interpretations
        
        question_lower = question.lower()
        
        # Add alternative intents based on keywords
        if "threat" in question_lower or "attack" in question_lower:
            if primary_intent.intent_type != SecurityIntentType.THREAT_HUNTING:
                alt_intent = SecurityIntent(
                    intent_type=SecurityIntentType.THREAT_HUNTING,
                    confidence=0.4,
                    original_question=question
                )
                possible_intents.append(alt_intent)
        
        if "compliance" in question_lower or "policy" in question_lower:
            if primary_intent.intent_type != SecurityIntentType.COMPLIANCE_CHECK:
                alt_intent = SecurityIntent(
                    intent_type=SecurityIntentType.COMPLIANCE_CHECK,
                    confidence=0.4,
                    original_question=question
                )
                possible_intents.append(alt_intent)
        
        if "risk" in question_lower or "vulnerability" in question_lower:
            if primary_intent.intent_type != SecurityIntentType.RISK_ASSESSMENT:
                alt_intent = SecurityIntent(
                    intent_type=SecurityIntentType.RISK_ASSESSMENT,
                    confidence=0.4,
                    original_question=question
                )
                possible_intents.append(alt_intent)
        
        return possible_intents
    
    def handle_clarification_response(
        self, 
        original_question: str,
        clarification_response: str,
        conversation_id: str
    ) -> Optional[str]:
        """
        Handle a user's response to clarification questions.
        
        Args:
            original_question: The original ambiguous question
            clarification_response: User's response to clarification
            conversation_id: ID for tracking the conversation
            
        Returns:
            Reformulated question or None if more clarification needed
        """
        # Store the clarification in conversation context
        if conversation_id not in self.conversation_context:
            self.conversation_context[conversation_id] = {
                'original_question': original_question,
                'clarifications': []
            }
        
        self.conversation_context[conversation_id]['clarifications'].append(clarification_response)
        
        # Attempt to reformulate the question based on clarification
        reformulated = self._reformulate_question(
            original_question, 
            clarification_response,
            self.conversation_context[conversation_id]['clarifications']
        )
        
        return reformulated
    
    def _reformulate_question(
        self, 
        original_question: str, 
        clarification: str,
        all_clarifications: List[str]
    ) -> str:
        """Reformulate the original question based on clarifications."""
        
        # Simple reformulation logic
        # In a production system, this would be more sophisticated
        
        clarification_lower = clarification.lower()
        
        # Add timeframe if provided
        timeframe_indicators = {
            "today": "today",
            "yesterday": "yesterday", 
            "last week": "last week",
            "last month": "last month",
            "24 hours": "last 24 hours",
            "past week": "past week"
        }
        
        timeframe = None
        for indicator, normalized in timeframe_indicators.items():
            if indicator in clarification_lower:
                timeframe = normalized
                break
        
        # Add system context if provided
        system_indicators = {
            "web server": "web servers",
            "database": "databases",
            "endpoint": "endpoints",
            "network": "network infrastructure",
            "email": "email systems"
        }
        
        system = None
        for indicator, normalized in system_indicators.items():
            if indicator in clarification_lower:
                system = normalized
                break
        
        # Reformulate the question
        reformulated = original_question
        
        if timeframe:
            reformulated += f" from {timeframe}"
        
        if system:
            reformulated += f" on {system}"
        
        return reformulated
    
    def get_conversation_context(self, conversation_id: str) -> Optional[Dict]:
        """Get the conversation context for a given conversation ID."""
        return self.conversation_context.get(conversation_id)
    
    def clear_conversation_context(self, conversation_id: str) -> None:
        """Clear the conversation context for a given conversation ID."""
        if conversation_id in self.conversation_context:
            del self.conversation_context[conversation_id]