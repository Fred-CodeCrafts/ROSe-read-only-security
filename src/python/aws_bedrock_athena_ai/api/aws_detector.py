"""
AWS Availability Detector Module

Detects if AWS services (Bedrock, Athena) are configured and available.
Caches results to avoid repeated AWS API calls.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AuthMode(Enum):
    """Authentication mode for the API"""
    DEMO = "demo"
    PRODUCTION = "production"


@dataclass
class AWSAvailabilityStatus:
    """AWS service availability status"""
    bedrock_available: bool
    athena_available: bool
    mode: AuthMode
    last_checked: datetime
    error_message: Optional[str] = None


class AWSAvailabilityDetector:
    """
    Detects AWS service availability with caching.
    
    Caches availability checks for 5 minutes to avoid repeated AWS calls.
    """
    
    def __init__(self, cache_ttl_seconds: int = 300):
        """
        Initialize the detector.
        
        Args:
            cache_ttl_seconds: Time to live for cache in seconds (default: 300 = 5 minutes)
        """
        self._bedrock_available: Optional[bool] = None
        self._athena_available: Optional[bool] = None
        self._last_check: Optional[datetime] = None
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._error_message: Optional[str] = None
    
    def _is_cache_valid(self) -> bool:
        """Check if cached results are still valid"""
        if self._last_check is None:
            return False
        return datetime.now() - self._last_check < self._cache_ttl
    
    def _check_demo_mode_env(self) -> bool:
        """Check if demo mode is explicitly enabled via environment variable"""
        return os.getenv('DEMO_MODE', '').lower() == 'true'
    
    def _check_aws_credentials(self) -> bool:
        """Check if AWS credentials are configured"""
        try:
            import boto3
            session = boto3.Session()
            credentials = session.get_credentials()
            return credentials is not None
        except Exception as e:
            logger.debug(f"AWS credentials check failed: {e}")
            return False
    
    def _check_bedrock_access(self) -> bool:
        """Check if AWS Bedrock is accessible"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Try to create Bedrock client
            bedrock = boto3.client('bedrock-runtime')
            
            # Lightweight check - just verify we can make a call
            # We don't actually list models as that might be expensive
            # Instead, we'll just verify the client was created successfully
            return True
            
        except NoCredentialsError:
            logger.debug("No AWS credentials found for Bedrock")
            return False
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'UnrecognizedClientException':
                logger.debug("AWS credentials invalid for Bedrock")
                return False
            # Other errors might be temporary, so we'll consider it available
            logger.debug(f"Bedrock client error: {e}")
            return False
        except Exception as e:
            logger.debug(f"Bedrock availability check failed: {e}")
            return False
    
    def _check_athena_config(self) -> bool:
        """Check if Athena is configured"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Check for Athena configuration
            database = os.getenv('ATHENA_DATABASE')
            table = os.getenv('ATHENA_TABLE')
            
            if not database or not table:
                logger.debug("Athena database or table not configured")
                return False
            
            # Try to create Athena client
            athena = boto3.client('athena')
            return True
            
        except NoCredentialsError:
            logger.debug("No AWS credentials found for Athena")
            return False
        except Exception as e:
            logger.debug(f"Athena availability check failed: {e}")
            return False
    
    def is_bedrock_available(self) -> bool:
        """
        Check if AWS Bedrock is configured and accessible.
        
        Returns:
            True if Bedrock is available, False otherwise
        """
        # Check for explicit demo mode
        if self._check_demo_mode_env():
            return False
        
        # Use cached result if valid
        if self._is_cache_valid() and self._bedrock_available is not None:
            return self._bedrock_available
        
        # Perform fresh check
        self._bedrock_available = (
            self._check_aws_credentials() and 
            self._check_bedrock_access()
        )
        self._last_check = datetime.now()
        
        return self._bedrock_available
    
    def is_athena_available(self) -> bool:
        """
        Check if Athena is configured.
        
        Returns:
            True if Athena is available, False otherwise
        """
        # Check for explicit demo mode
        if self._check_demo_mode_env():
            return False
        
        # Use cached result if valid
        if self._is_cache_valid() and self._athena_available is not None:
            return self._athena_available
        
        # Perform fresh check
        self._athena_available = (
            self._check_aws_credentials() and 
            self._check_athena_config()
        )
        self._last_check = datetime.now()
        
        return self._athena_available
    
    def get_availability_status(self) -> Dict:
        """
        Get comprehensive availability status.
        
        Returns:
            Dictionary with availability status for all services
        """
        bedrock = self.is_bedrock_available()
        athena = self.is_athena_available()
        
        mode = AuthMode.PRODUCTION if bedrock else AuthMode.DEMO
        
        return {
            "bedrock": bedrock,
            "athena": athena,
            "mode": mode.value,
            "last_checked": self._last_check.isoformat() if self._last_check else None,
            "error_message": self._error_message
        }
    
    def clear_cache(self):
        """Clear cached availability results"""
        self._bedrock_available = None
        self._athena_available = None
        self._last_check = None
        self._error_message = None
