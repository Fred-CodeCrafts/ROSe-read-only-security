"""
Log Redactor

Advanced PII and secret pattern detection and redaction system.
Implements comprehensive redaction for access keys, tokens, emails, IP addresses, phone numbers.
"""

import re
import logging
import datetime
from typing import List, Dict, Pattern, Tuple
from .models import RedactionResult, RedactionMatch, RedactionType, DataProtectionPolicy


class LogRedactor:
    """
    Advanced log redaction system with comprehensive PII and secret detection.
    
    Provides real-time redaction of sensitive information from logs and text data
    to prevent accidental exposure of credentials, personal information, and secrets.
    """
    
    # Comprehensive redaction patterns with high precision
    REDACTION_PATTERNS = {
        RedactionType.AWS_ACCESS_KEY: [
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
            r'ASIA[0-9A-Z]{16}',  # AWS Temporary Access Key ID
        ],
        RedactionType.AWS_SECRET_KEY: [
            r'[A-Za-z0-9+/]{40}',  # AWS Secret Access Key (40 chars base64)
        ],
        RedactionType.EMAIL: [
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',  # Email addresses
        ],
        RedactionType.IP_ADDRESS: [
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',  # IPv4
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',  # IPv6
        ],
        RedactionType.PHONE_NUMBER: [
            r'\b\d{3}-\d{3}-\d{4}\b',  # US phone format XXX-XXX-XXXX
            r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',  # US phone format (XXX) XXX-XXXX
            r'\b\d{10}\b',  # 10 digit phone numbers
        ],
        RedactionType.SSN: [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format XXX-XX-XXXX
            r'\b\d{9}\b',  # 9 digit SSN without dashes
        ],
        RedactionType.PASSWORD: [
            r'password\s*[:=]\s*[^"\s\n]+',  # password fields
            r'pwd\s*[:=]\s*[^"\s\n]+',  # pwd fields
            r'pass\s*[:=]\s*[^"\s\n]+',  # pass fields
        ],
        RedactionType.TOKEN: [
            r'token["\s]*[:=]["\s]*[^"\s\n]+',  # token fields
            r'bearer\s+[A-Za-z0-9\-._~+/]+=*',  # Bearer tokens
            r'jwt\s+[A-Za-z0-9\-._~+/]+=*',  # JWT tokens
        ],
        RedactionType.CREDIT_CARD: [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',  # MasterCard
            r'\b3[47][0-9]{13}\b',  # American Express
        ],
        RedactionType.API_KEY: [
            r'api[_-]?key["\s]*[:=]["\s]*[^"\s\n]+',  # API key fields
            r'secret[_-]?key["\s]*[:=]["\s]*[^"\s\n]+',  # Secret key fields
            r'client[_-]?secret["\s]*[:=]["\s]*[^"\s\n]+',  # Client secret fields
        ],
    }
    
    def __init__(self, policy: DataProtectionPolicy = None):
        """
        Initialize LogRedactor with optional policy configuration.
        
        Args:
            policy: Data protection policy configuration
        """
        self.policy = policy or DataProtectionPolicy()
        self.compiled_patterns = self._compile_patterns()
        self.logger = logging.getLogger(__name__)
        
    def _compile_patterns(self) -> Dict[RedactionType, List[Pattern]]:
        """Compile regex patterns for efficient matching"""
        compiled = {}
        for redaction_type, patterns in self.REDACTION_PATTERNS.items():
            compiled[redaction_type] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
        return compiled
    
    def _is_pattern_enabled(self, redaction_type: RedactionType) -> bool:
        """Check if a redaction pattern is enabled in the policy"""
        pattern_enabled_map = {
            RedactionType.EMAIL: self.policy.enable_email_redaction,
            RedactionType.IP_ADDRESS: self.policy.enable_ip_redaction,
            RedactionType.PHONE_NUMBER: self.policy.enable_phone_redaction,
            RedactionType.SSN: self.policy.enable_ssn_redaction,
            RedactionType.AWS_ACCESS_KEY: self.policy.enable_aws_key_redaction,
            RedactionType.AWS_SECRET_KEY: self.policy.enable_aws_key_redaction,
            RedactionType.PASSWORD: self.policy.enable_password_redaction,
            RedactionType.TOKEN: self.policy.enable_token_redaction,
            RedactionType.CREDIT_CARD: self.policy.enable_credit_card_redaction,
            RedactionType.API_KEY: self.policy.enable_api_key_redaction,
        }
        return pattern_enabled_map.get(redaction_type, True)
    
    def detect_patterns(self, text: str) -> List[RedactionMatch]:
        """
        Detect all sensitive patterns in the given text.
        
        Args:
            text: Text to analyze for sensitive patterns
            
        Returns:
            List of RedactionMatch objects for detected patterns
        """
        matches = []
        
        for redaction_type, patterns in self.compiled_patterns.items():
            if not self._is_pattern_enabled(redaction_type):
                continue
                
            for pattern in patterns:
                for match in pattern.finditer(text):
                    redaction_match = RedactionMatch(
                        pattern_type=redaction_type,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        original_text=match.group(),
                        confidence=self._calculate_confidence(redaction_type, match.group())
                    )
                    
                    # Only include matches above confidence threshold
                    if redaction_match.confidence >= self.policy.min_confidence_threshold:
                        matches.append(redaction_match)
        
        # Sort matches by position for consistent processing
        matches.sort(key=lambda x: x.start_pos)
        return matches
    
    def _calculate_confidence(self, redaction_type: RedactionType, matched_text: str) -> float:
        """
        Calculate confidence score for a pattern match.
        
        Args:
            redaction_type: Type of pattern matched
            matched_text: The matched text
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        # Base confidence scores by pattern type
        base_confidence = {
            RedactionType.AWS_ACCESS_KEY: 0.95,  # Very specific format
            RedactionType.AWS_SECRET_KEY: 0.85,  # Could be other base64
            RedactionType.EMAIL: 0.90,  # Email format is distinctive
            RedactionType.IP_ADDRESS: 0.85,  # Could be version numbers
            RedactionType.PHONE_NUMBER: 0.80,  # Could be other numbers
            RedactionType.SSN: 0.90,  # Very specific format
            RedactionType.PASSWORD: 0.85,  # Increased confidence for password patterns
            RedactionType.TOKEN: 0.80,  # Context-dependent
            RedactionType.CREDIT_CARD: 0.95,  # Very specific format
            RedactionType.API_KEY: 0.85,  # Increased confidence for API key patterns
        }
        
        confidence = base_confidence.get(redaction_type, 0.8)
        
        # Adjust confidence based on context and length
        if redaction_type in [RedactionType.PASSWORD, RedactionType.TOKEN, RedactionType.API_KEY]:
            # Higher confidence for longer secrets
            if len(matched_text) > 20:
                confidence += 0.1
            elif len(matched_text) < 8:
                confidence -= 0.1  # Reduced penalty
        
        return min(1.0, max(0.0, confidence))
    
    def redact_log(self, log_message: str) -> RedactionResult:
        """
        Redact sensitive information from a log message.
        
        Args:
            log_message: Original log message to redact
            
        Returns:
            RedactionResult with original text, redacted text, and match details
        """
        matches = self.detect_patterns(log_message)
        
        if not matches:
            return RedactionResult(
                original_text=log_message,
                redacted_text=log_message,
                matches=[],
                redaction_count=0,
                timestamp=datetime.datetime.now()
            )
        
        # Remove overlapping matches - keep the one with highest confidence
        non_overlapping_matches = self._remove_overlapping_matches(matches)
        
        # Apply redactions from end to start to preserve positions
        redacted_text = log_message
        redaction_count = 0
        
        for match in reversed(non_overlapping_matches):
            redacted_text = (
                redacted_text[:match.start_pos] +
                self.policy.redaction_placeholder +
                redacted_text[match.end_pos:]
            )
            redaction_count += 1
        
        result = RedactionResult(
            original_text=log_message,
            redacted_text=redacted_text,
            matches=non_overlapping_matches,
            redaction_count=redaction_count,
            timestamp=datetime.datetime.now()
        )
        
        # Log redaction activity for audit trail
        self.logger.info(f"Redacted {redaction_count} sensitive patterns from log message")
        
        return result
    
    def _remove_overlapping_matches(self, matches: List[RedactionMatch]) -> List[RedactionMatch]:
        """Remove overlapping matches, keeping the one with highest confidence"""
        if not matches:
            return matches
        
        # Sort by start position
        sorted_matches = sorted(matches, key=lambda x: x.start_pos)
        non_overlapping = []
        
        for match in sorted_matches:
            # Check if this match overlaps with any already selected match
            overlaps = False
            for selected in non_overlapping:
                if (match.start_pos < selected.end_pos and match.end_pos > selected.start_pos):
                    # There's an overlap - keep the one with higher confidence
                    if match.confidence > selected.confidence:
                        non_overlapping.remove(selected)
                        non_overlapping.append(match)
                    overlaps = True
                    break
            
            if not overlaps:
                non_overlapping.append(match)
        
        return sorted(non_overlapping, key=lambda x: x.start_pos)
    
    def redact_batch(self, log_messages: List[str]) -> List[RedactionResult]:
        """
        Redact sensitive information from multiple log messages.
        
        Args:
            log_messages: List of log messages to redact
            
        Returns:
            List of RedactionResult objects
        """
        return [self.redact_log(message) for message in log_messages]
    
    def get_redaction_stats(self, results: List[RedactionResult]) -> Dict[str, int]:
        """
        Get statistics about redaction operations.
        
        Args:
            results: List of RedactionResult objects
            
        Returns:
            Dictionary with redaction statistics
        """
        stats = {
            'total_messages': len(results),
            'messages_with_redactions': sum(1 for r in results if r.redaction_count > 0),
            'total_redactions': sum(r.redaction_count for r in results),
        }
        
        # Count by pattern type
        pattern_counts = {}
        for result in results:
            for match in result.matches:
                pattern_type = match.pattern_type.value
                pattern_counts[pattern_type] = pattern_counts.get(pattern_type, 0) + 1
        
        stats['redactions_by_type'] = pattern_counts
        return stats