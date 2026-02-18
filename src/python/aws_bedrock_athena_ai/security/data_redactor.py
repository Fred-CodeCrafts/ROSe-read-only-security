"""
Sensitive data redaction for AI Security Analyst outputs.

This module provides comprehensive data redaction capabilities to ensure
that sensitive information is not exposed in analysis results, reports,
or logs while maintaining the utility of the security insights.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import hashlib

from aws_bedrock_athena_ai.security.models import RedactionRule, RedactionResult, DataClassification

logger = logging.getLogger(__name__)


class SensitiveDataRedactor:
    """
    Handles redaction of sensitive data from security analysis outputs.
    
    Provides configurable redaction rules for different types of sensitive
    information including PII, credentials, network information, and more.
    """
    
    def __init__(self):
        """Initialize the data redactor with default rules."""
        self.redaction_rules: List[RedactionRule] = []
        
        # Cache for compiled regex patterns
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        
        # Statistics tracking
        self.redaction_stats = {
            'total_redactions': 0,
            'redactions_by_type': {},
            'processing_time_total': 0.0
        }
        
        # Initialize default rules after setting up the instance variables
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default redaction rules for common sensitive data types."""
        
        # Email addresses
        self.add_redaction_rule(
            pattern_name="email_addresses",
            pattern_regex=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            replacement="[EMAIL_REDACTED]",
            data_classification=DataClassification.CONFIDENTIAL
        )
        
        # Credit card numbers (basic pattern)
        self.add_redaction_rule(
            pattern_name="credit_cards",
            pattern_regex=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            replacement="[CREDIT_CARD_REDACTED]",
            data_classification=DataClassification.RESTRICTED
        )
        
        # Social Security Numbers (US format)
        self.add_redaction_rule(
            pattern_name="ssn",
            pattern_regex=r'\b\d{3}-?\d{2}-?\d{4}\b',
            replacement="[SSN_REDACTED]",
            data_classification=DataClassification.RESTRICTED
        )
        
        # Phone numbers (various formats)
        self.add_redaction_rule(
            pattern_name="phone_numbers",
            pattern_regex=r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            replacement="[PHONE_REDACTED]",
            data_classification=DataClassification.CONFIDENTIAL
        )
        
        # IP addresses (IPv4)
        self.add_redaction_rule(
            pattern_name="ipv4_addresses",
            pattern_regex=r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            replacement="[IP_REDACTED]",
            data_classification=DataClassification.INTERNAL
        )
        
        # AWS Access Keys
        self.add_redaction_rule(
            pattern_name="aws_access_keys",
            pattern_regex=r'\bAKIA[0-9A-Z]{16}\b',
            replacement="[AWS_ACCESS_KEY_REDACTED]",
            data_classification=DataClassification.RESTRICTED
        )
        
        # AWS Secret Keys (partial pattern)
        self.add_redaction_rule(
            pattern_name="aws_secret_keys",
            pattern_regex=r'\b[A-Za-z0-9/+=]{40}\b',
            replacement="[AWS_SECRET_REDACTED]",
            data_classification=DataClassification.RESTRICTED
        )
        
        # Generic passwords in logs
        self.add_redaction_rule(
            pattern_name="password_fields",
            pattern_regex=r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*[^\s\n]+',
            replacement=r'\1: [PASSWORD_REDACTED]',
            data_classification=DataClassification.RESTRICTED
        )
        
        # API keys (generic pattern)
        self.add_redaction_rule(
            pattern_name="api_keys",
            pattern_regex=r'(?i)(api[_-]?key|token)[\s]*[:=][\s]*[a-zA-Z0-9_-]{20,}',
            replacement=r'\1: [API_KEY_REDACTED]',
            data_classification=DataClassification.RESTRICTED
        )
        
        # MAC addresses
        self.add_redaction_rule(
            pattern_name="mac_addresses",
            pattern_regex=r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
            replacement="[MAC_ADDRESS_REDACTED]",
            data_classification=DataClassification.INTERNAL
        )
        
        # URLs with potential sensitive parameters
        self.add_redaction_rule(
            pattern_name="sensitive_urls",
            pattern_regex=r'https?://[^\s]+(?:token|key|password|secret)=[^\s&]+',
            replacement="[SENSITIVE_URL_REDACTED]",
            data_classification=DataClassification.CONFIDENTIAL
        )
        
        logger.info(f"Initialized {len(self.redaction_rules)} default redaction rules")
    
    def add_redaction_rule(self, pattern_name: str, pattern_regex: str, 
                          replacement: str, data_classification: DataClassification,
                          enabled: bool = True):
        """Add a new redaction rule."""
        rule = RedactionRule(
            pattern_name=pattern_name,
            pattern_regex=pattern_regex,
            replacement=replacement,
            data_classification=data_classification,
            enabled=enabled
        )
        
        self.redaction_rules.append(rule)
        
        # Compile and cache the regex pattern
        try:
            self._compiled_patterns[pattern_name] = re.compile(pattern_regex)
            logger.debug(f"Added redaction rule: {pattern_name}")
        except re.error as e:
            logger.error(f"Invalid regex pattern for rule {pattern_name}: {e}")
            # Remove the invalid rule
            self.redaction_rules.pop()
    
    def redact_text(self, text: str, classification_level: Optional[DataClassification] = None) -> RedactionResult:
        """
        Redact sensitive data from text based on configured rules.
        
        Args:
            text: The text to redact
            classification_level: Optional classification level to limit redaction scope
            
        Returns:
            RedactionResult with original text, redacted text, and metadata
        """
        start_time = datetime.utcnow()
        
        if not text or not text.strip():
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                redactions_made=[],
                classification_level=DataClassification.PUBLIC,
                processing_time_ms=0.0
            )
        
        redacted_text = text
        redactions_made = []
        max_classification = DataClassification.PUBLIC
        
        # Apply each enabled redaction rule
        for rule in self.redaction_rules:
            if not rule.enabled:
                continue
                
            # Skip rules that are more restrictive than requested level
            if classification_level and rule.data_classification.value > classification_level.value:
                continue
            
            pattern = self._compiled_patterns.get(rule.pattern_name)
            if not pattern:
                continue
            
            # Find all matches
            matches = list(pattern.finditer(redacted_text))
            if matches:
                # Track the highest classification level found
                if rule.data_classification.value > max_classification.value:
                    max_classification = rule.data_classification
                
                # Apply redactions (in reverse order to maintain positions)
                for match in reversed(matches):
                    original_value = match.group(0)
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # Generate replacement text
                    if '\\1' in rule.replacement:
                        # Handle regex groups in replacement
                        replacement_text = pattern.sub(rule.replacement, original_value)
                    else:
                        replacement_text = rule.replacement
                    
                    # Apply redaction
                    redacted_text = redacted_text[:start_pos] + replacement_text + redacted_text[end_pos:]
                    
                    # Record the redaction
                    redactions_made.append({
                        'rule_name': rule.pattern_name,
                        'original_value_hash': hashlib.sha256(original_value.encode()).hexdigest()[:16],
                        'position': start_pos,
                        'length': len(original_value),
                        'classification': rule.data_classification.value,
                        'replacement': replacement_text
                    })
                
                # Update statistics
                self.redaction_stats['redactions_by_type'][rule.pattern_name] = \
                    self.redaction_stats['redactions_by_type'].get(rule.pattern_name, 0) + len(matches)
        
        # Update total statistics
        self.redaction_stats['total_redactions'] += len(redactions_made)
        
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        self.redaction_stats['processing_time_total'] += processing_time
        
        logger.debug(f"Redacted {len(redactions_made)} sensitive items from text "
                    f"(classification: {max_classification.value})")
        
        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            redactions_made=redactions_made,
            classification_level=max_classification,
            processing_time_ms=processing_time
        )
    
    def redact_structured_data(self, data: Dict[str, Any], 
                             classification_level: Optional[DataClassification] = None) -> Dict[str, Any]:
        """
        Redact sensitive data from structured data (dictionaries, lists).
        
        Args:
            data: The structured data to redact
            classification_level: Optional classification level to limit redaction scope
            
        Returns:
            Dictionary with redacted values
        """
        if not isinstance(data, dict):
            return data
        
        redacted_data = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # Redact string values
                redaction_result = self.redact_text(value, classification_level)
                redacted_data[key] = redaction_result.redacted_text
            elif isinstance(value, dict):
                # Recursively redact nested dictionaries
                redacted_data[key] = self.redact_structured_data(value, classification_level)
            elif isinstance(value, list):
                # Redact list items
                redacted_data[key] = [
                    self.redact_text(item, classification_level).redacted_text 
                    if isinstance(item, str) else item
                    for item in value
                ]
            else:
                # Keep non-string values as-is
                redacted_data[key] = value
        
        return redacted_data
    
    def redact_security_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive data from a security analysis report.
        
        This method applies appropriate redaction levels to different sections
        of a security report based on the sensitivity of the content.
        """
        redacted_report = {}
        
        # Define redaction levels for different report sections
        section_classifications = {
            'executive_summary': DataClassification.INTERNAL,
            'technical_details': DataClassification.CONFIDENTIAL,
            'raw_logs': DataClassification.RESTRICTED,
            'recommendations': DataClassification.INTERNAL,
            'evidence': DataClassification.CONFIDENTIAL,
            'affected_systems': DataClassification.CONFIDENTIAL
        }
        
        for section, content in report.items():
            classification = section_classifications.get(section, DataClassification.INTERNAL)
            
            if isinstance(content, str):
                redaction_result = self.redact_text(content, classification)
                redacted_report[section] = redaction_result.redacted_text
            elif isinstance(content, dict):
                redacted_report[section] = self.redact_structured_data(content, classification)
            elif isinstance(content, list):
                redacted_report[section] = [
                    self.redact_text(item, classification).redacted_text 
                    if isinstance(item, str) else item
                    for item in content
                ]
            else:
                redacted_report[section] = content
        
        return redacted_report
    
    def get_redaction_statistics(self) -> Dict[str, Any]:
        """Get statistics about redaction operations."""
        return {
            'total_redactions': self.redaction_stats['total_redactions'],
            'redactions_by_type': dict(self.redaction_stats['redactions_by_type']),
            'total_processing_time_ms': self.redaction_stats['processing_time_total'],
            'active_rules': len([rule for rule in self.redaction_rules if rule.enabled]),
            'total_rules': len(self.redaction_rules)
        }
    
    def enable_rule(self, pattern_name: str):
        """Enable a redaction rule."""
        for rule in self.redaction_rules:
            if rule.pattern_name == pattern_name:
                rule.enabled = True
                logger.info(f"Enabled redaction rule: {pattern_name}")
                return
        logger.warning(f"Redaction rule not found: {pattern_name}")
    
    def disable_rule(self, pattern_name: str):
        """Disable a redaction rule."""
        for rule in self.redaction_rules:
            if rule.pattern_name == pattern_name:
                rule.enabled = False
                logger.info(f"Disabled redaction rule: {pattern_name}")
                return
        logger.warning(f"Redaction rule not found: {pattern_name}")
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List all redaction rules with their status."""
        return [
            {
                'pattern_name': rule.pattern_name,
                'enabled': rule.enabled,
                'classification': rule.data_classification.value,
                'replacement': rule.replacement
            }
            for rule in self.redaction_rules
        ]