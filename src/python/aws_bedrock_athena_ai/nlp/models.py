"""
Data models for Natural Language Processing components.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum


class SecurityIntentType(Enum):
    """Types of security intents that can be recognized."""
    THREAT_HUNTING = "threat_hunting"
    COMPLIANCE_CHECK = "compliance_check"
    RISK_ASSESSMENT = "risk_assessment"
    INCIDENT_INVESTIGATION = "incident_investigation"
    VULNERABILITY_SCAN = "vulnerability_scan"
    ACCESS_REVIEW = "access_review"
    ANOMALY_DETECTION = "anomaly_detection"
    SECURITY_POSTURE = "security_posture"
    ATTACK_SURFACE = "attack_surface"
    DATA_BREACH = "data_breach"
    UNKNOWN = "unknown"


class EntityType(Enum):
    """Types of entities that can be extracted from security questions."""
    TIMEFRAME = "timeframe"
    SYSTEM = "system"
    IP_ADDRESS = "ip_address"
    USER = "user"
    THREAT_TYPE = "threat_type"
    SEVERITY = "severity"
    PROTOCOL = "protocol"
    PORT = "port"
    DOMAIN = "domain"
    FILE_TYPE = "file_type"


@dataclass
class SecurityEntity:
    """Represents an entity extracted from a security question."""
    entity_type: EntityType
    value: str
    confidence: float
    start_pos: int = 0
    end_pos: int = 0
    normalized_value: Optional[str] = None


@dataclass
class TimeRange:
    """Represents a time range for security analysis."""
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    relative_description: Optional[str] = None  # e.g., "last week", "past 24 hours"
    
    @classmethod
    def from_relative_description(cls, description: str) -> 'TimeRange':
        """Create TimeRange from relative descriptions like 'last week', 'past 24 hours'."""
        now = datetime.now()
        description = description.lower().strip()
        
        if "last week" in description or "past week" in description:
            return cls(
                start=now - timedelta(weeks=1),
                end=now,
                relative_description=description
            )
        elif "last 24 hours" in description or "past 24 hours" in description:
            return cls(
                start=now - timedelta(hours=24),
                end=now,
                relative_description=description
            )
        elif "last month" in description or "past month" in description:
            return cls(
                start=now - timedelta(days=30),
                end=now,
                relative_description=description
            )
        elif "today" in description:
            return cls(
                start=now.replace(hour=0, minute=0, second=0, microsecond=0),
                end=now,
                relative_description=description
            )
        else:
            return cls(relative_description=description)


@dataclass
class SecurityIntent:
    """Represents the recognized intent from a security question."""
    intent_type: SecurityIntentType
    entities: List[SecurityEntity] = field(default_factory=list)
    confidence: float = 0.0
    clarification_needed: bool = False
    clarification_questions: List[str] = field(default_factory=list)
    original_question: str = ""
    
    def get_entities_by_type(self, entity_type: EntityType) -> List[SecurityEntity]:
        """Get all entities of a specific type."""
        return [entity for entity in self.entities if entity.entity_type == entity_type]
    
    def has_entity_type(self, entity_type: EntityType) -> bool:
        """Check if intent contains entities of a specific type."""
        return any(entity.entity_type == entity_type for entity in self.entities)


@dataclass
class QueryContext:
    """Context information extracted from security questions."""
    timeframe: Optional[TimeRange] = None
    systems: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    priority_level: str = "medium"  # low, medium, high, critical
    user_role: str = "analyst"  # analyst, executive, admin, user
    conversation_history: List[str] = field(default_factory=list)
    
    # Additional context fields
    threat_types: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    
    def add_to_history(self, question: str) -> None:
        """Add a question to the conversation history."""
        self.conversation_history.append(question)
        # Keep only last 10 questions to avoid memory issues
        if len(self.conversation_history) > 10:
            self.conversation_history = self.conversation_history[-10:]


@dataclass
class DisambiguationRequest:
    """Request for query disambiguation when the intent is unclear."""
    original_question: str
    possible_intents: List[SecurityIntent]
    clarification_questions: List[str]
    suggested_reformulations: List[str] = field(default_factory=list)
    
    def get_top_intent(self) -> Optional[SecurityIntent]:
        """Get the most confident intent."""
        if not self.possible_intents:
            return None
        return max(self.possible_intents, key=lambda x: x.confidence)


@dataclass
class NLPResponse:
    """Response from natural language processing."""
    intent: SecurityIntent
    context: QueryContext
    disambiguation: Optional[DisambiguationRequest] = None
    processing_time_ms: float = 0.0
    
    @property
    def needs_clarification(self) -> bool:
        """Check if the response needs clarification from the user."""
        return self.intent.clarification_needed or self.disambiguation is not None