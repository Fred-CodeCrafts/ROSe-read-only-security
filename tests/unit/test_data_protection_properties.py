"""
Property-Based Tests for Data Protection

Tests Property 10: Comprehensive Data Protection
Validates Requirements 2.7, 2.8, 2.9
"""

import pytest
from hypothesis import given, strategies as st, settings, example, HealthCheck
from hypothesis.strategies import composite
import datetime
import re
from typing import List, Dict, Any

from src.python.data_protection import (
    LogRedactor, SyntheticDataValidator, DataClassifier,
    RedactionType, DataClassification, DataProtectionPolicy
)


# Test data generators
@composite
def sensitive_data_strategy(draw):
    """Generate data containing sensitive patterns"""
    # Simplified and faster pattern generation
    pattern_type = draw(st.sampled_from(['aws_key', 'email', 'ip', 'phone', 'password']))
    
    if pattern_type == 'aws_key':
        key = f"AKIA{draw(st.text(alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', min_size=16, max_size=16))}"
        normal_text = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz ', min_size=5, max_size=20))
        return f"{normal_text} {key}"
    elif pattern_type == 'email':
        user = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz', min_size=3, max_size=8))
        domain = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz', min_size=3, max_size=8))
        normal_text = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz ', min_size=5, max_size=20))
        return f"{normal_text} {user}@{domain}.com"
    elif pattern_type == 'ip':
        ip = f"{draw(st.integers(min_value=1, max_value=255))}.{draw(st.integers(min_value=0, max_value=255))}.{draw(st.integers(min_value=0, max_value=255))}.{draw(st.integers(min_value=1, max_value=255))}"
        normal_text = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz ', min_size=5, max_size=20))
        return f"{normal_text} {ip}"
    elif pattern_type == 'phone':
        phone = f"{draw(st.integers(min_value=100, max_value=999))}-{draw(st.integers(min_value=100, max_value=999))}-{draw(st.integers(min_value=1000, max_value=9999))}"
        normal_text = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz ', min_size=5, max_size=20))
        return f"{normal_text} {phone}"
    else:  # password
        password = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', min_size=8, max_size=15))
        normal_text = draw(st.text(alphabet='abcdefghijklmnopqrstuvwxyz ', min_size=5, max_size=20))
        return f"{normal_text} password={password}"


@composite
def synthetic_dataset_strategy(draw):
    """Generate synthetic datasets for validation"""
    dataset_types = ['dict', 'list', 'string']
    dataset_type = draw(st.sampled_from(dataset_types))
    
    if dataset_type == 'dict':
        return draw(st.dictionaries(
            st.text(alphabet='abcdefghijklmnopqrstuvwxyz_', min_size=3, max_size=15),
            st.one_of(
                st.text(min_size=1, max_size=50),
                st.integers(),
                st.floats(allow_nan=False, allow_infinity=False)
            ),
            min_size=1, max_size=10
        ))
    elif dataset_type == 'list':
        return draw(st.lists(
            st.text(min_size=1, max_size=50),
            min_size=1, max_size=20
        ))
    else:
        return draw(st.text(min_size=10, max_size=200))


@composite
def real_data_patterns_strategy(draw):
    """Generate data that looks like real data"""
    real_patterns = [
        "john.smith@gmail.com",
        "jane.doe@yahoo.com", 
        "admin@microsoft.com",
        "test@google.com",
        "John Smith",
        "Jane Doe",
        "password123",
        "admin",
        "12345",
        "123456789"
    ]
    
    num_patterns = draw(st.integers(min_value=1, max_value=3))
    selected_patterns = draw(st.lists(st.sampled_from(real_patterns), min_size=num_patterns, max_size=num_patterns))
    
    normal_text = draw(st.text(min_size=10, max_size=100))
    combined_text = normal_text + " " + " ".join(selected_patterns)
    
    return combined_text


class TestDataProtectionProperties:
    """Property-based tests for comprehensive data protection"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.redactor = LogRedactor()
        self.validator = SyntheticDataValidator()
        self.classifier = DataClassifier()
    
    @given(sensitive_data_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    @example("AKIA1234567890123456 user@example.com 192.168.1.1")
    def test_property_10_comprehensive_redaction(self, sensitive_text: str):
        """
        Property 10: Comprehensive Data Protection - Redaction Component
        
        For any text containing sensitive patterns (credentials, PII, secrets),
        the LogRedactor should detect and redact all sensitive information
        while preserving the overall structure and readability of the text.
        
        **Validates: Requirements 2.7, 2.8, 2.9**
        """
        # Test the redaction
        result = self.redactor.redact_log(sensitive_text)
        
        # Property: Redacted text should not contain original sensitive patterns
        assert result.redacted_text != sensitive_text, "Redaction should modify text containing sensitive data"
        assert result.redaction_count > 0, "Should detect and count redactions"
        assert len(result.matches) > 0, "Should detect pattern matches"
        
        # Property: All detected patterns should be redacted
        for match in result.matches:
            assert match.original_text not in result.redacted_text, f"Pattern '{match.original_text}' should be redacted"
        
        # Property: Redacted text should contain redaction placeholders
        assert "[REDACTED]" in result.redacted_text, "Redacted text should contain redaction placeholders"
        
        # Property: Redaction should be consistent
        redaction_count_in_text = result.redacted_text.count("[REDACTED]")
        assert redaction_count_in_text == result.redaction_count, "Redaction count should match actual redactions"
        
        # Property: Original text should be preserved in result
        assert result.original_text == sensitive_text, "Original text should be preserved"
        
        # Property: Timestamp should be recent
        time_diff = datetime.datetime.now() - result.timestamp
        assert time_diff.total_seconds() < 60, "Timestamp should be recent"
    
    @given(synthetic_dataset_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_property_10_synthetic_data_validation(self, dataset: Any):
        """
        Property 10: Comprehensive Data Protection - Synthetic Data Validation
        
        For any dataset that is genuinely synthetic (generated, not real),
        the SyntheticDataValidator should correctly identify it as synthetic
        and provide appropriate confidence scores.
        
        **Validates: Requirements 2.8, 2.9**
        """
        # Test synthetic data validation
        result = self.validator.validate_dataset(dataset)
        
        # Property: Validation should complete successfully
        assert result.timestamp is not None, "Validation should have timestamp"
        assert 0.0 <= result.confidence_score <= 1.0, "Confidence score should be between 0 and 1"
        
        # Property: Detected real patterns should be a list
        assert isinstance(result.detected_real_patterns, list), "Detected patterns should be a list"
        assert isinstance(result.validation_errors, list), "Validation errors should be a list"
        
        # Property: If no real patterns detected, should have reasonable confidence
        if len(result.detected_real_patterns) == 0:
            assert result.confidence_score >= 0.2, "Should have reasonable confidence for clean synthetic data"
        
        # Property: Boolean result should be consistent with findings
        if result.is_synthetic:
            assert len(result.detected_real_patterns) == 0, "Synthetic data should have no real patterns"
        
        # Property: Validation should be deterministic for same input
        result2 = self.validator.validate_dataset(dataset)
        assert result.is_synthetic == result2.is_synthetic, "Validation should be deterministic"
    
    @given(real_data_patterns_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_property_10_real_data_detection(self, real_data_text: str):
        """
        Property 10: Comprehensive Data Protection - Real Data Detection
        
        For any text containing patterns that appear to be real data,
        the SyntheticDataValidator should detect these patterns and
        flag the data as potentially containing real information.
        
        **Validates: Requirements 2.8, 2.9**
        """
        # Test real data detection
        result = self.validator.validate_dataset(real_data_text)
        
        # Property: Should detect some real patterns in obviously real data
        if any(pattern in real_data_text.lower() for pattern in ['gmail.com', 'yahoo.com', 'microsoft.com', 'google.com']):
            assert len(result.detected_real_patterns) > 0, "Should detect real email domain patterns"
        
        # Property: Confidence should reflect real data detection
        if len(result.detected_real_patterns) > 0:
            assert result.confidence_score < 0.8, "Should have lower confidence when real patterns detected"
        
        # Property: Should not classify as synthetic if real patterns found
        if len(result.detected_real_patterns) > 2:  # Multiple real patterns
            assert not result.is_synthetic, "Should not classify as synthetic when multiple real patterns found"
    
    @given(st.text(min_size=10, max_size=200))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_property_10_data_classification_consistency(self, text_data: str):
        """
        Property 10: Comprehensive Data Protection - Data Classification
        
        For any text data, the DataClassifier should provide consistent
        classification results and appropriate confidence scores based
        on the sensitivity patterns detected in the content.
        
        **Validates: Requirements 2.7**
        """
        # Test data classification
        classification, confidence, patterns = self.classifier.classify_data(text_data)
        
        # Property: Classification should be valid enum value
        assert isinstance(classification, DataClassification), "Should return valid classification"
        
        # Property: Confidence should be reasonable
        assert 0.0 <= confidence <= 1.0, "Confidence should be between 0 and 1"
        assert confidence >= 0.3, "Should have minimum confidence threshold"
        
        # Property: Patterns should be a list
        assert isinstance(patterns, list), "Detected patterns should be a list"
        
        # Property: Classification should be deterministic
        classification2, confidence2, patterns2 = self.classifier.classify_data(text_data)
        assert classification == classification2, "Classification should be deterministic"
        assert confidence == confidence2, "Confidence should be deterministic"
        
        # Property: Higher sensitivity patterns should result in higher classification
        if any(sensitive_word in text_data.lower() for sensitive_word in ['password', 'secret', 'ssn', 'credit card']):
            assert classification in [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED], \
                "Sensitive content should get high classification"
        
        # Property: Protection requirements should match classification
        requirements = self.classifier.get_protection_requirements(classification)
        assert isinstance(requirements, dict), "Should return protection requirements"
        assert 'encryption_required' in requirements, "Should specify encryption requirements"
        assert 'access_logging' in requirements, "Should specify access logging requirements"
    
    @given(st.lists(sensitive_data_strategy(), min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_property_10_batch_processing_consistency(self, sensitive_texts: List[str]):
        """
        Property 10: Comprehensive Data Protection - Batch Processing
        
        For any batch of texts containing sensitive data, batch processing
        should produce the same results as individual processing and
        maintain consistency across all operations.
        
        **Validates: Requirements 2.7, 2.8, 2.9**
        """
        # Test batch redaction
        batch_results = self.redactor.redact_batch(sensitive_texts)
        individual_results = [self.redactor.redact_log(text) for text in sensitive_texts]
        
        # Property: Batch and individual processing should be equivalent
        assert len(batch_results) == len(individual_results), "Batch should process all items"
        assert len(batch_results) == len(sensitive_texts), "Should process all input texts"
        
        for batch_result, individual_result in zip(batch_results, individual_results):
            assert batch_result.redacted_text == individual_result.redacted_text, \
                "Batch and individual redaction should be identical"
            assert batch_result.redaction_count == individual_result.redaction_count, \
                "Redaction counts should match"
        
        # Property: Statistics should be accurate
        stats = self.redactor.get_redaction_stats(batch_results)
        assert stats['total_messages'] == len(sensitive_texts), "Should count all messages"
        assert stats['total_redactions'] == sum(r.redaction_count for r in batch_results), \
            "Should count all redactions"
        
        # Property: All messages with sensitive data should have redactions
        messages_with_redactions = sum(1 for r in batch_results if r.redaction_count > 0)
        assert stats['messages_with_redactions'] == messages_with_redactions, \
            "Should accurately count messages with redactions"
    
    @given(st.dictionaries(
        st.text(alphabet='abcdefghijklmnopqrstuvwxyz_', min_size=3, max_size=15),
        st.text(min_size=1, max_size=100),
        min_size=1, max_size=10
    ))
    @settings(max_examples=50)
    def test_property_10_policy_enforcement(self, test_data: Dict[str, str]):
        """
        Property 10: Comprehensive Data Protection - Policy Enforcement
        
        For any data protection policy configuration, the system should
        consistently enforce the policy rules and provide appropriate
        protection levels based on the configured settings.
        
        **Validates: Requirements 2.7**
        """
        # Test with restrictive policy
        restrictive_policy = DataProtectionPolicy(
            enable_email_redaction=True,
            enable_ip_redaction=True,
            enable_password_redaction=True,
            min_confidence_threshold=0.5
        )
        
        # Test with permissive policy  
        permissive_policy = DataProtectionPolicy(
            enable_email_redaction=False,
            enable_ip_redaction=False,
            enable_password_redaction=False,
            min_confidence_threshold=0.9
        )
        
        restrictive_redactor = LogRedactor(restrictive_policy)
        permissive_redactor = LogRedactor(permissive_policy)
        
        # Convert test data to string
        test_text = str(test_data)
        
        # Test both policies
        restrictive_result = restrictive_redactor.redact_log(test_text)
        permissive_result = permissive_redactor.redact_log(test_text)
        
        # Property: Restrictive policy should redact more or equal
        assert restrictive_result.redaction_count >= permissive_result.redaction_count, \
            "Restrictive policy should redact more patterns"
        
        # Property: Policy settings should be respected
        assert restrictive_redactor.policy.enable_email_redaction == True, "Policy should be applied"
        assert permissive_redactor.policy.enable_email_redaction == False, "Policy should be applied"
        
        # Property: Confidence thresholds should be enforced
        for match in restrictive_result.matches:
            assert match.confidence >= restrictive_policy.min_confidence_threshold, \
                "Should respect confidence threshold"
        
        for match in permissive_result.matches:
            assert match.confidence >= permissive_policy.min_confidence_threshold, \
                "Should respect confidence threshold"


if __name__ == "__main__":
    # Run the property tests
    pytest.main([__file__, "-v", "--tb=short"])