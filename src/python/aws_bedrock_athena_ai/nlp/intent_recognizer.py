"""
Security Intent Recognition System.

This module provides intent classification for security-related questions,
identifying what type of security analysis the user is requesting.
"""

import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import logging

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, SecurityIntentType, SecurityEntity, EntityType

logger = logging.getLogger(__name__)


@dataclass
class IntentPattern:
    """Pattern for matching security intents."""
    intent_type: SecurityIntentType
    keywords: List[str]
    patterns: List[str]  # Regex patterns
    confidence_boost: float = 0.0  # Additional confidence for strong matches


class SecurityIntentRecognizer:
    """
    Recognizes security intents from natural language questions.
    
    Uses pattern matching and keyword analysis to classify security questions
    into specific intent types like threat hunting, compliance checks, etc.
    """
    
    def __init__(self):
        self.intent_patterns = self._initialize_intent_patterns()
        self.entity_patterns = self._initialize_entity_patterns()
    
    def _initialize_intent_patterns(self) -> List[IntentPattern]:
        """Initialize patterns for recognizing different security intents."""
        return [
            # Threat Hunting
            IntentPattern(
                intent_type=SecurityIntentType.THREAT_HUNTING,
                keywords=[
                    "attack", "threat", "malware", "suspicious", "intrusion", 
                    "breach", "compromise", "exploit", "malicious", "hacker",
                    "being attacked", "under attack", "security incident"
                ],
                patterns=[
                    r"are we (being )?attacked",
                    r"is .* (being )?attacked",
                    r"detect.* threat",
                    r"find.* malware",
                    r"hunt.* threat",
                    r"suspicious.* activity",
                    r"security.* incident"
                ],
                confidence_boost=0.2
            ),
            
            # Risk Assessment
            IntentPattern(
                intent_type=SecurityIntentType.RISK_ASSESSMENT,
                keywords=[
                    "risk", "vulnerability", "exposure", "weakness", "security posture",
                    "assess", "evaluation", "score", "rating", "security level"
                ],
                patterns=[
                    r"what.* risk",
                    r"assess.* security",
                    r"security.* posture",
                    r"vulnerability.* assessment",
                    r"risk.* level",
                    r"how secure",
                    r"security.* score"
                ],
                confidence_boost=0.15
            ),
            
            # Compliance Check
            IntentPattern(
                intent_type=SecurityIntentType.COMPLIANCE_CHECK,
                keywords=[
                    "compliance", "policy", "regulation", "standard", "audit",
                    "gdpr", "hipaa", "sox", "pci", "iso", "nist", "cis"
                ],
                patterns=[
                    r"compliance.* check",
                    r"policy.* violation",
                    r"audit.* result",
                    r"regulatory.* compliance",
                    r"(gdpr|hipaa|sox|pci|iso|nist|cis).* compliance"
                ],
                confidence_boost=0.25
            ),
            
            # Incident Investigation
            IntentPattern(
                intent_type=SecurityIntentType.INCIDENT_INVESTIGATION,
                keywords=[
                    "investigate", "incident", "forensic", "timeline", "root cause",
                    "what happened", "how did", "trace", "analyze incident"
                ],
                patterns=[
                    r"what happened",
                    r"investigate.* incident",
                    r"forensic.* analysis",
                    r"incident.* timeline",
                    r"root.* cause",
                    r"how did.* happen"
                ],
                confidence_boost=0.2
            ),
            
            # Vulnerability Scan
            IntentPattern(
                intent_type=SecurityIntentType.VULNERABILITY_SCAN,
                keywords=[
                    "vulnerability", "cve", "patch", "update", "scan", "weakness",
                    "security hole", "exploit", "missing patch"
                ],
                patterns=[
                    r"vulnerability.* scan",
                    r"missing.* patch",
                    r"cve.* check",
                    r"security.* hole",
                    r"outdated.* software"
                ],
                confidence_boost=0.15
            ),
            
            # Access Review
            IntentPattern(
                intent_type=SecurityIntentType.ACCESS_REVIEW,
                keywords=[
                    "access", "permission", "privilege", "user", "login", "authentication",
                    "authorization", "account", "credential", "password"
                ],
                patterns=[
                    r"access.* review",
                    r"user.* permission",
                    r"privilege.* escalation",
                    r"unauthorized.* access",
                    r"login.* attempt",
                    r"failed.* authentication"
                ],
                confidence_boost=0.1
            ),
            
            # Anomaly Detection
            IntentPattern(
                intent_type=SecurityIntentType.ANOMALY_DETECTION,
                keywords=[
                    "anomaly", "unusual", "abnormal", "strange", "unexpected",
                    "outlier", "deviation", "pattern", "baseline"
                ],
                patterns=[
                    r"unusual.* activity",
                    r"abnormal.* behavior",
                    r"detect.* anomaly",
                    r"strange.* pattern",
                    r"unexpected.* traffic"
                ],
                confidence_boost=0.1
            ),
            
            # Data Breach
            IntentPattern(
                intent_type=SecurityIntentType.DATA_BREACH,
                keywords=[
                    "data breach", "data leak", "exposed data", "stolen data",
                    "confidential", "sensitive", "exfiltration", "data loss"
                ],
                patterns=[
                    r"data.* breach",
                    r"data.* leak",
                    r"exposed.* data",
                    r"stolen.* data",
                    r"data.* exfiltration"
                ],
                confidence_boost=0.3
            )
        ]
    
    def _initialize_entity_patterns(self) -> Dict[EntityType, List[str]]:
        """Initialize patterns for extracting entities from questions."""
        return {
            EntityType.TIMEFRAME: [
                r"(last|past)\s+(week|month|day|hour|year)",
                r"(today|yesterday|this week|this month)",
                r"in the (last|past)\s+\d+\s+(days?|hours?|weeks?|months?)",
                r"\d{1,2}/\d{1,2}/\d{4}",  # Date format
                r"\d{4}-\d{2}-\d{2}"       # ISO date format
            ],
            EntityType.IP_ADDRESS: [
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IPv4
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"  # IPv6 (simplified)
            ],
            EntityType.SYSTEM: [
                r"\b(server|database|web server|application|system|host)\b",
                r"\b\w+\.(com|org|net|edu|gov)\b",  # Domain names
                r"\b(windows|linux|unix|macos|centos|ubuntu)\b"
            ],
            EntityType.USER: [
                r"\buser\s+\w+",
                r"\baccount\s+\w+",
                r"\b\w+@\w+\.\w+\b"  # Email addresses
            ],
            EntityType.THREAT_TYPE: [
                r"\b(malware|virus|trojan|ransomware|phishing|ddos|sql injection)\b",
                r"\b(brute force|privilege escalation|lateral movement)\b"
            ],
            EntityType.SEVERITY: [
                r"\b(critical|high|medium|low|severe|minor)\b"
            ]
        }
    
    def recognize_intent(self, question: str) -> SecurityIntent:
        """
        Recognize the security intent from a natural language question.
        
        Args:
            question: The security question to analyze
            
        Returns:
            SecurityIntent with recognized intent type, entities, and confidence
        """
        question_lower = question.lower().strip()
        
        # Calculate confidence scores for each intent type
        intent_scores = {}
        
        for pattern in self.intent_patterns:
            score = self._calculate_intent_score(question_lower, pattern)
            if score > 0:
                intent_scores[pattern.intent_type] = score
        
        # Determine the best intent
        if not intent_scores:
            best_intent = SecurityIntentType.UNKNOWN
            confidence = 0.0
        else:
            best_intent = max(intent_scores.keys(), key=lambda x: intent_scores[x])
            confidence = min(intent_scores[best_intent], 1.0)
        
        # Extract entities
        entities = self._extract_entities(question)
        
        # Determine if clarification is needed
        clarification_needed = confidence < 0.3 or best_intent == SecurityIntentType.UNKNOWN
        clarification_questions = []
        
        if clarification_needed:
            clarification_questions = self._generate_clarification_questions(
                question, intent_scores
            )
        
        return SecurityIntent(
            intent_type=best_intent,
            entities=entities,
            confidence=confidence,
            clarification_needed=clarification_needed,
            clarification_questions=clarification_questions,
            original_question=question
        )
    
    def _calculate_intent_score(self, question: str, pattern: IntentPattern) -> float:
        """Calculate confidence score for a specific intent pattern."""
        score = 0.0
        
        # Check keyword matches
        keyword_matches = sum(1 for keyword in pattern.keywords if keyword in question)
        if keyword_matches > 0:
            score += (keyword_matches / len(pattern.keywords)) * 0.6
        
        # Check regex pattern matches
        pattern_matches = 0
        for regex_pattern in pattern.patterns:
            if re.search(regex_pattern, question, re.IGNORECASE):
                pattern_matches += 1
        
        if pattern_matches > 0:
            score += (pattern_matches / len(pattern.patterns)) * 0.4
            score += pattern.confidence_boost
        
        return score
    
    def _extract_entities(self, question: str) -> List[SecurityEntity]:
        """Extract entities from the security question."""
        entities = []
        
        for entity_type, patterns in self.entity_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, question, re.IGNORECASE)
                for match in matches:
                    entity = SecurityEntity(
                        entity_type=entity_type,
                        value=match.group(),
                        confidence=0.8,  # Default confidence for regex matches
                        start_pos=match.start(),
                        end_pos=match.end(),
                        normalized_value=self._normalize_entity_value(
                            entity_type, match.group()
                        )
                    )
                    entities.append(entity)
        
        return entities
    
    def _normalize_entity_value(self, entity_type: EntityType, value: str) -> str:
        """Normalize entity values for consistent processing."""
        value = value.strip().lower()
        
        if entity_type == EntityType.TIMEFRAME:
            # Normalize timeframe expressions
            if "last week" in value or "past week" in value:
                return "last_week"
            elif "last month" in value or "past month" in value:
                return "last_month"
            elif "today" in value:
                return "today"
            elif "yesterday" in value:
                return "yesterday"
        
        elif entity_type == EntityType.SEVERITY:
            # Normalize severity levels
            if value in ["critical", "severe"]:
                return "critical"
            elif value in ["high"]:
                return "high"
            elif value in ["medium", "moderate"]:
                return "medium"
            elif value in ["low", "minor"]:
                return "low"
        
        return value
    
    def _generate_clarification_questions(
        self, 
        question: str, 
        intent_scores: Dict[SecurityIntentType, float]
    ) -> List[str]:
        """Generate clarification questions when intent is unclear."""
        questions = []
        
        if not intent_scores:
            questions.append(
                "I'm not sure what type of security analysis you're looking for. "
                "Are you asking about threats, compliance, vulnerabilities, or something else?"
            )
        elif len(intent_scores) > 1:
            # Multiple possible intents
            top_intents = sorted(intent_scores.keys(), 
                               key=lambda x: intent_scores[x], reverse=True)[:2]
            
            intent_descriptions = {
                SecurityIntentType.THREAT_HUNTING: "threat detection and hunting",
                SecurityIntentType.RISK_ASSESSMENT: "security risk assessment",
                SecurityIntentType.COMPLIANCE_CHECK: "compliance checking",
                SecurityIntentType.INCIDENT_INVESTIGATION: "incident investigation",
                SecurityIntentType.VULNERABILITY_SCAN: "vulnerability scanning",
                SecurityIntentType.ACCESS_REVIEW: "access and permission review"
            }
            
            descriptions = [intent_descriptions.get(intent, str(intent)) 
                          for intent in top_intents]
            
            questions.append(
                f"Are you asking about {descriptions[0]} or {descriptions[1]}?"
            )
        
        # Check for missing context
        if "timeframe" not in question.lower():
            questions.append("What time period should I analyze?")
        
        if not any(word in question.lower() for word in ["system", "server", "application"]):
            questions.append("Which systems or applications should I focus on?")
        
        return questions[:2]  # Limit to 2 clarification questions