"""
Synthetic Data Validator

Validates that datasets contain only synthetic data and detects real data patterns.
Implements quality assurance for synthetic data generation.
"""

import re
import logging
import datetime
from typing import List, Dict, Any, Set, Optional
from faker import Faker
from .models import ValidationResult


class SyntheticDataValidator:
    """
    Validates that datasets contain only synthetic data and no real PII.
    
    Provides comprehensive validation to ensure test datasets are safe
    and contain no real personal information or sensitive data.
    """
    
    # Known real data patterns to detect
    REAL_DATA_PATTERNS = {
        'common_real_emails': [
            r'@gmail\.com$',
            r'@yahoo\.com$', 
            r'@hotmail\.com$',
            r'@outlook\.com$',
            r'@aol\.com$',
        ],
        'common_real_names': [
            # Common real names that shouldn't appear in synthetic data
            r'\bJohn\s+Smith\b',
            r'\bJane\s+Doe\b',
            r'\bMichael\s+Johnson\b',
            r'\bChris\s+Brown\b',
            r'\bDavid\s+Wilson\b',
        ],
        'real_company_domains': [
            r'@microsoft\.com$',
            r'@google\.com$',
            r'@amazon\.com$',
            r'@apple\.com$',
            r'@facebook\.com$',
            r'@twitter\.com$',
        ],
        'sequential_patterns': [
            # Patterns that suggest real data
            r'\b12345\b',
            r'\b123456789\b',
            r'\btest123\b',
            r'\bpassword\b',
            r'\badmin\b',
        ],
    }
    
    # Faker domains that indicate synthetic data
    SYNTHETIC_INDICATORS = {
        'faker_domains': [
            'example.com',
            'example.org', 
            'example.net',
            'test.com',
            'fake.com',
            'dummy.com',
        ],
        'faker_patterns': [
            r'faker_\d+',
            r'synthetic_\d+',
            r'test_user_\d+',
            r'dummy_\d+',
        ],
    }
    
    def __init__(self):
        """Initialize the synthetic data validator"""
        self.faker = Faker()
        self.logger = logging.getLogger(__name__)
        self.compiled_real_patterns = self._compile_real_patterns()
        self.compiled_synthetic_patterns = self._compile_synthetic_patterns()
        
    def _compile_real_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile real data detection patterns"""
        compiled = {}
        for category, patterns in self.REAL_DATA_PATTERNS.items():
            compiled[category] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in patterns
            ]
        return compiled
        
    def _compile_synthetic_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile synthetic data detection patterns"""
        compiled = {}
        for category, patterns in self.SYNTHETIC_INDICATORS.items():
            compiled[category] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in patterns
            ]
        return compiled
    
    def validate_dataset(self, dataset: Any) -> ValidationResult:
        """
        Validate that a dataset contains only synthetic data.
        
        Args:
            dataset: Dataset to validate (dict, list, or string)
            
        Returns:
            ValidationResult with validation status and details
        """
        detected_real_patterns = []
        validation_errors = []
        
        # Convert dataset to string for pattern matching
        dataset_str = self._dataset_to_string(dataset)
        
        # Check for real data patterns
        for category, patterns in self.compiled_real_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(dataset_str)
                if matches:
                    detected_real_patterns.extend([
                        f"{category}: {match}" for match in matches
                    ])
        
        # Additional real data detection for common patterns
        additional_real_checks = [
            (r'@(gmail|yahoo|hotmail|outlook|aol)\.com', 'common_real_emails'),
            (r'\b(john|jane|michael|david|chris)\s+(smith|doe|johnson|brown|wilson)\b', 'common_real_names'),
            (r'@(microsoft|google|amazon|apple|facebook|twitter)\.com', 'real_company_domains'),
            (r'\b(password|admin|test123|12345)\b', 'sequential_patterns'),
        ]
        
        for pattern_str, category in additional_real_checks:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = pattern.findall(dataset_str)
            if matches:
                detected_real_patterns.extend([
                    f"{category}: {match}" for match in matches
                ])
        
        # Calculate synthetic score
        synthetic_score = self._calculate_synthetic_score(dataset_str)
        
        # Reduce synthetic score based on real patterns detected
        if detected_real_patterns:
            # Reduce confidence significantly when real patterns are found
            penalty = min(0.6, len(detected_real_patterns) * 0.2)
            synthetic_score = max(0.1, synthetic_score - penalty)
        
        # Validate data structure
        structure_errors = self._validate_data_structure(dataset)
        validation_errors.extend(structure_errors)
        
        # Determine if data is synthetic
        is_synthetic = (
            len(detected_real_patterns) == 0 and
            len(validation_errors) == 0 and
            synthetic_score > 0.2  # Lower threshold for synthetic classification
        )
        
        result = ValidationResult(
            is_synthetic=is_synthetic,
            confidence_score=synthetic_score,
            detected_real_patterns=detected_real_patterns,
            validation_errors=validation_errors,
            timestamp=datetime.datetime.now()
        )
        
        # Log validation results
        if not is_synthetic:
            self.logger.warning(f"Dataset validation failed: {len(detected_real_patterns)} real patterns detected")
        else:
            self.logger.info("Dataset validation passed: contains only synthetic data")
            
        return result
    
    def _dataset_to_string(self, dataset: Any) -> str:
        """Convert dataset to string for pattern matching"""
        if isinstance(dataset, str):
            return dataset
        elif isinstance(dataset, dict):
            return str(dataset)
        elif isinstance(dataset, list):
            return ' '.join(str(item) for item in dataset)
        else:
            return str(dataset)
    
    def _calculate_synthetic_score(self, dataset_str: str) -> float:
        """
        Calculate how synthetic the data appears to be.
        
        Args:
            dataset_str: String representation of dataset
            
        Returns:
            Score between 0.0 (likely real) and 1.0 (likely synthetic)
        """
        synthetic_indicators = 0
        total_checks = 0
        
        # Check for synthetic domain indicators
        for category, patterns in self.compiled_synthetic_patterns.items():
            for pattern in patterns:
                if pattern.search(dataset_str):
                    synthetic_indicators += 1
                total_checks += 1
        
        # Check for faker-like patterns
        faker_patterns = [
            r'\w+\d{4,}@example\.(com|org|net)',  # Faker email patterns
            r'[A-Z][a-z]+\s+[A-Z][a-z]+\d+',     # Name with numbers
            r'\+1-\d{3}-\d{3}-\d{4}',             # Faker phone format
        ]
        
        for pattern_str in faker_patterns:
            pattern = re.compile(pattern_str)
            if pattern.search(dataset_str):
                synthetic_indicators += 1
            total_checks += 1
        
        # Base score - start with higher baseline for unknown data
        if total_checks == 0:
            base_score = 0.7  # Assume synthetic if no clear indicators
        else:
            base_score = max(0.2, synthetic_indicators / total_checks)  # Minimum 0.2 baseline
        
        # Adjust score based on data characteristics
        if len(dataset_str) < 100:
            base_score += 0.2  # Small datasets are more likely synthetic
        
        # Check for patterns that suggest synthetic data
        if any(indicator in dataset_str.lower() for indicator in ['test', 'fake', 'dummy', 'example']):
            base_score += 0.3
        
        # Check for sequential or pattern-like data (suggests synthetic)
        if re.search(r'(\d)\1{3,}', dataset_str):  # Repeated digits like 0000
            base_score += 0.2
        
        return min(1.0, max(0.0, base_score))
    
    def _validate_data_structure(self, dataset: Any) -> List[str]:
        """
        Validate the structure of the dataset for synthetic data compliance.
        
        Args:
            dataset: Dataset to validate
            
        Returns:
            List of validation errors
        """
        errors = []
        
        if isinstance(dataset, dict):
            errors.extend(self._validate_dict_structure(dataset))
        elif isinstance(dataset, list):
            errors.extend(self._validate_list_structure(dataset))
        
        return errors
    
    def _validate_dict_structure(self, data: Dict[str, Any]) -> List[str]:
        """Validate dictionary structure for synthetic data compliance"""
        errors = []
        
        # Check for suspicious field names
        suspicious_fields = ['real_', 'production_', 'live_', 'actual_']
        for field in data.keys():
            if any(sus in field.lower() for sus in suspicious_fields):
                errors.append(f"Suspicious field name: {field}")
        
        # Check for empty or null values that might indicate real data placeholders
        for key, value in data.items():
            if value is None or (isinstance(value, str) and value.strip() == ''):
                errors.append(f"Empty value for field: {key}")
        
        return errors
    
    def _validate_list_structure(self, data: List[Any]) -> List[str]:
        """Validate list structure for synthetic data compliance"""
        errors = []
        
        # Check for consistent data types
        if data:
            first_type = type(data[0])
            if not all(isinstance(item, first_type) for item in data):
                errors.append("Inconsistent data types in list")
        
        # Check for duplicate entries (might indicate copy-paste from real data)
        if len(data) != len(set(str(item) for item in data)):
            errors.append("Duplicate entries detected")
        
        return errors
    
    def generate_synthetic_replacement(self, detected_pattern: str) -> str:
        """
        Generate a synthetic replacement for detected real data.
        
        Args:
            detected_pattern: The real data pattern that was detected
            
        Returns:
            Synthetic replacement data
        """
        # Simple replacement logic based on pattern type
        if '@' in detected_pattern:
            return self.faker.email()
        elif any(char.isdigit() for char in detected_pattern):
            if len(detected_pattern) == 10:
                return self.faker.phone_number()
            else:
                return self.faker.random_number(digits=len([c for c in detected_pattern if c.isdigit()]))
        else:
            return self.faker.name()
    
    def create_quality_report(self, validation_results: List[ValidationResult]) -> Dict[str, Any]:
        """
        Create a quality assurance report for synthetic data validation.
        
        Args:
            validation_results: List of validation results
            
        Returns:
            Quality report dictionary
        """
        total_datasets = len(validation_results)
        synthetic_datasets = sum(1 for r in validation_results if r.is_synthetic)
        
        report = {
            'total_datasets_validated': total_datasets,
            'synthetic_datasets': synthetic_datasets,
            'real_data_detected': total_datasets - synthetic_datasets,
            'overall_synthetic_rate': synthetic_datasets / total_datasets if total_datasets > 0 else 0,
            'average_confidence_score': sum(r.confidence_score for r in validation_results) / total_datasets if total_datasets > 0 else 0,
            'common_real_patterns': [],
            'validation_errors': [],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Collect common real patterns
        all_real_patterns = []
        all_errors = []
        for result in validation_results:
            all_real_patterns.extend(result.detected_real_patterns)
            all_errors.extend(result.validation_errors)
        
        # Count pattern frequencies
        pattern_counts = {}
        for pattern in all_real_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        report['common_real_patterns'] = sorted(
            pattern_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]  # Top 10 most common
        
        report['validation_errors'] = list(set(all_errors))
        
        return report