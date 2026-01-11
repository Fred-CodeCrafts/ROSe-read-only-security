"""
Data Classifier

Real-time data classification and protection policies.
Implements automated data classification based on content analysis.
"""

import re
import logging
import datetime
from typing import Dict, List, Any, Optional, Tuple
from .models import DataClassification, DataProtectionPolicy


class DataClassifier:
    """
    Real-time data classification system for automatic data protection.
    
    Analyzes data content and assigns appropriate classification levels
    based on sensitivity patterns and protection policies.
    """
    
    # Classification patterns by sensitivity level
    CLASSIFICATION_PATTERNS = {
        DataClassification.RESTRICTED: [
            r'social\s*security\s*number',
            r'ssn',
            r'credit\s*card',
            r'bank\s*account',
            r'routing\s*number',
            r'passport\s*number',
            r'driver\s*license',
            r'medical\s*record',
            r'health\s*information',
            r'biometric',
            r'genetic\s*data',
        ],
        DataClassification.CONFIDENTIAL: [
            r'password',
            r'secret\s*key',
            r'api\s*key',
            r'access\s*token',
            r'private\s*key',
            r'certificate',
            r'credential',
            r'authentication',
            r'salary',
            r'compensation',
            r'financial\s*data',
            r'trade\s*secret',
            r'proprietary',
        ],
        DataClassification.INTERNAL: [
            r'employee\s*id',
            r'internal\s*use',
            r'company\s*confidential',
            r'business\s*plan',
            r'strategy',
            r'roadmap',
            r'budget',
            r'forecast',
            r'performance\s*data',
            r'metrics',
            r'analytics',
        ],
        DataClassification.PUBLIC: [
            r'public\s*information',
            r'press\s*release',
            r'marketing',
            r'documentation',
            r'help\s*text',
            r'user\s*guide',
            r'faq',
            r'contact\s*information',
        ],
    }
    
    # Content type indicators
    CONTENT_TYPE_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'url': r'https?://[^\s]+',
        'file_path': r'[a-zA-Z]:\\[^<>:"|?*\n\r]+|/[^<>:"|?*\n\r]+',
        'json': r'^\s*[\{\[].*[\}\]]\s*$',
        'xml': r'<[^>]+>.*</[^>]+>',
        'sql': r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b',
    }
    
    def __init__(self, policy: DataProtectionPolicy = None):
        """
        Initialize data classifier with protection policy.
        
        Args:
            policy: Data protection policy configuration
        """
        self.policy = policy or DataProtectionPolicy()
        self.logger = logging.getLogger(__name__)
        self.compiled_patterns = self._compile_classification_patterns()
        self.compiled_content_patterns = self._compile_content_patterns()
        
    def _compile_classification_patterns(self) -> Dict[DataClassification, List[re.Pattern]]:
        """Compile classification patterns for efficient matching"""
        compiled = {}
        for classification, patterns in self.CLASSIFICATION_PATTERNS.items():
            compiled[classification] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
        return compiled
    
    def _compile_content_patterns(self) -> Dict[str, re.Pattern]:
        """Compile content type patterns"""
        return {
            content_type: re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for content_type, pattern in self.CONTENT_TYPE_PATTERNS.items()
        }
    
    def classify_data(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Tuple[DataClassification, float, List[str]]:
        """
        Classify data based on content analysis.
        
        Args:
            data: Data to classify (string, dict, list, etc.)
            context: Optional context information (filename, source, etc.)
            
        Returns:
            Tuple of (classification, confidence_score, detected_patterns)
        """
        # Convert data to string for analysis
        data_str = self._data_to_string(data)
        
        # Analyze content patterns
        detected_patterns = []
        classification_scores = {
            DataClassification.RESTRICTED: 0.0,
            DataClassification.CONFIDENTIAL: 0.0,
            DataClassification.INTERNAL: 0.0,
            DataClassification.PUBLIC: 0.0,
        }
        
        # Check classification patterns
        for classification, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(data_str)
                if matches:
                    # Weight by number of matches and pattern specificity
                    score_increment = len(matches) * self._get_pattern_weight(classification)
                    classification_scores[classification] += score_increment
                    detected_patterns.extend([f"{classification.value}: {pattern.pattern}" for _ in matches])
        
        # Apply context-based adjustments
        if context:
            self._apply_context_adjustments(classification_scores, context, data_str)
        
        # Determine final classification
        final_classification = max(classification_scores.items(), key=lambda x: x[1])
        classification = final_classification[0]
        raw_score = final_classification[1]
        
        # Calculate confidence score
        total_score = sum(classification_scores.values())
        confidence = raw_score / total_score if total_score > 0 else 0.0
        
        # Apply minimum thresholds
        if confidence < 0.3:
            classification = DataClassification.INTERNAL  # Default to internal if uncertain
            confidence = 0.3
        
        self.logger.info(f"Classified data as {classification.value} with confidence {confidence:.2f}")
        
        return classification, confidence, detected_patterns
    
    def _data_to_string(self, data: Any) -> str:
        """Convert data to string for pattern analysis"""
        if isinstance(data, str):
            return data
        elif isinstance(data, dict):
            # Include both keys and values for classification
            return ' '.join([str(k) + ' ' + str(v) for k, v in data.items()])
        elif isinstance(data, list):
            return ' '.join(str(item) for item in data)
        else:
            return str(data)
    
    def _get_pattern_weight(self, classification: DataClassification) -> float:
        """Get weight for classification pattern matches"""
        weights = {
            DataClassification.RESTRICTED: 1.0,    # Highest weight
            DataClassification.CONFIDENTIAL: 0.8,
            DataClassification.INTERNAL: 0.6,
            DataClassification.PUBLIC: 0.4,       # Lowest weight
        }
        return weights.get(classification, 0.5)
    
    def _apply_context_adjustments(self, scores: Dict[DataClassification, float], 
                                 context: Dict[str, Any], data_str: str):
        """Apply context-based classification adjustments"""
        # File extension context
        if 'filename' in context:
            filename = context['filename'].lower()
            if any(ext in filename for ext in ['.key', '.pem', '.p12', '.crt']):
                scores[DataClassification.CONFIDENTIAL] += 0.5
            elif any(ext in filename for ext in ['.md', '.txt', '.html', '.pdf']):
                scores[DataClassification.PUBLIC] += 0.2
        
        # Source context
        if 'source' in context:
            source = context['source'].lower()
            if 'public' in source or 'docs' in source:
                scores[DataClassification.PUBLIC] += 0.3
            elif 'secret' in source or 'private' in source:
                scores[DataClassification.CONFIDENTIAL] += 0.3
        
        # Content type context
        content_types = self.detect_content_types(data_str)
        if 'sql' in content_types:
            scores[DataClassification.INTERNAL] += 0.2
        if 'json' in content_types or 'xml' in content_types:
            scores[DataClassification.INTERNAL] += 0.1
    
    def detect_content_types(self, data_str: str) -> List[str]:
        """Detect content types in the data"""
        detected_types = []
        for content_type, pattern in self.compiled_content_patterns.items():
            if pattern.search(data_str):
                detected_types.append(content_type)
        return detected_types
    
    def get_protection_requirements(self, classification: DataClassification) -> Dict[str, Any]:
        """
        Get protection requirements for a given classification level.
        
        Args:
            classification: Data classification level
            
        Returns:
            Dictionary of protection requirements
        """
        requirements = {
            DataClassification.RESTRICTED: {
                'encryption_required': True,
                'access_logging': True,
                'retention_period_days': 2555,  # 7 years
                'access_approval_required': True,
                'backup_encryption': True,
                'geographic_restrictions': True,
                'audit_frequency': 'monthly',
            },
            DataClassification.CONFIDENTIAL: {
                'encryption_required': True,
                'access_logging': True,
                'retention_period_days': 1825,  # 5 years
                'access_approval_required': True,
                'backup_encryption': True,
                'geographic_restrictions': False,
                'audit_frequency': 'quarterly',
            },
            DataClassification.INTERNAL: {
                'encryption_required': False,
                'access_logging': True,
                'retention_period_days': 1095,  # 3 years
                'access_approval_required': False,
                'backup_encryption': False,
                'geographic_restrictions': False,
                'audit_frequency': 'annually',
            },
            DataClassification.PUBLIC: {
                'encryption_required': False,
                'access_logging': False,
                'retention_period_days': 365,   # 1 year
                'access_approval_required': False,
                'backup_encryption': False,
                'geographic_restrictions': False,
                'audit_frequency': 'none',
            },
        }
        
        return requirements.get(classification, requirements[DataClassification.INTERNAL])
    
    def create_classification_report(self, classifications: List[Tuple[Any, DataClassification, float]]) -> Dict[str, Any]:
        """
        Create a classification report for multiple data items.
        
        Args:
            classifications: List of (data, classification, confidence) tuples
            
        Returns:
            Classification report dictionary
        """
        total_items = len(classifications)
        
        # Count by classification
        classification_counts = {}
        confidence_scores = []
        
        for _, classification, confidence in classifications:
            classification_counts[classification.value] = classification_counts.get(classification.value, 0) + 1
            confidence_scores.append(confidence)
        
        report = {
            'total_items_classified': total_items,
            'classification_distribution': classification_counts,
            'average_confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0,
            'high_confidence_items': sum(1 for score in confidence_scores if score > 0.8),
            'low_confidence_items': sum(1 for score in confidence_scores if score < 0.5),
            'timestamp': datetime.datetime.now().isoformat(),
        }
        
        # Add protection requirements summary
        protection_summary = {}
        for classification in DataClassification:
            count = classification_counts.get(classification.value, 0)
            if count > 0:
                requirements = self.get_protection_requirements(classification)
                protection_summary[classification.value] = {
                    'count': count,
                    'requirements': requirements
                }
        
        report['protection_requirements'] = protection_summary
        
        return report