"""
Authentication and authorization for the API.

This module now integrates with the comprehensive security middleware
while maintaining backward compatibility for API key authentication.
"""

import hashlib
import secrets
import time
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import logging

from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Import the new security middleware
from aws_bedrock_athena_ai.security.middleware import security_middleware
from aws_bedrock_athena_ai.security.models import SecurityContext, ResourceType

logger = logging.getLogger(__name__)

# Simple in-memory storage for demo purposes
# In production, use a proper database
API_KEYS: Dict[str, Dict] = {}
RATE_LIMITS: Dict[str, List[float]] = {}

security = HTTPBearer()


class AuthManager:
    """Manages API authentication and authorization."""
    
    def __init__(self):
        self.rate_limit_window = 3600  # 1 hour in seconds
        self.default_rate_limit = 100  # requests per hour
        
    def generate_api_key(self, name: str, permissions: List[str] = None) -> Dict[str, str]:
        """Generate a new API key."""
        if permissions is None:
            permissions = ["query"]
            
        # Generate secure random key
        key = secrets.token_urlsafe(32)
        key_id = secrets.token_urlsafe(16)
        
        # Hash the key for storage (store hash, not plain key)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        # Store key metadata
        API_KEYS[key_hash] = {
            "key_id": key_id,
            "name": name,
            "permissions": permissions,
            "created_at": datetime.utcnow(),
            "last_used": None,
            "usage_count": 0
        }
        
        logger.info(f"Generated API key '{name}' with ID {key_id}")
        
        return {
            "api_key": key,
            "key_id": key_id,
            "name": name,
            "permissions": permissions
        }
    
    def validate_api_key(self, key: str) -> Optional[Dict]:
        """Validate an API key and return key metadata."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        if key_hash in API_KEYS:
            key_data = API_KEYS[key_hash]
            
            # Update usage statistics
            key_data["last_used"] = datetime.utcnow()
            key_data["usage_count"] += 1
            
            return key_data
        
        return None
    
    def check_rate_limit(self, key_hash: str) -> bool:
        """Check if the API key is within rate limits."""
        current_time = time.time()
        
        # Initialize rate limit tracking for new keys
        if key_hash not in RATE_LIMITS:
            RATE_LIMITS[key_hash] = []
        
        # Clean old requests outside the window
        RATE_LIMITS[key_hash] = [
            req_time for req_time in RATE_LIMITS[key_hash]
            if current_time - req_time < self.rate_limit_window
        ]
        
        # Check if under limit
        if len(RATE_LIMITS[key_hash]) < self.default_rate_limit:
            RATE_LIMITS[key_hash].append(current_time)
            return True
        
        return False
    
    def get_rate_limit_info(self, key_hash: str) -> Dict:
        """Get rate limit information for a key."""
        current_time = time.time()
        
        if key_hash not in RATE_LIMITS:
            RATE_LIMITS[key_hash] = []
        
        # Clean old requests
        RATE_LIMITS[key_hash] = [
            req_time for req_time in RATE_LIMITS[key_hash]
            if current_time - req_time < self.rate_limit_window
        ]
        
        requests_made = len(RATE_LIMITS[key_hash])
        requests_remaining = max(0, self.default_rate_limit - requests_made)
        
        # Calculate reset time (start of next hour)
        reset_time = datetime.fromtimestamp(
            current_time + (self.rate_limit_window - (current_time % self.rate_limit_window))
        )
        
        return {
            "requests_remaining": requests_remaining,
            "reset_time": reset_time,
            "limit_per_hour": self.default_rate_limit
        }


# Global auth manager instance
auth_manager = AuthManager()


async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Security(security)) -> SecurityContext:
    """
    Dependency to get current authenticated user using the security middleware.
    
    This function now uses the comprehensive security middleware for authentication
    while maintaining backward compatibility.
    """
    try:
        # Use the security middleware for authentication
        security_context = await security_middleware.authenticate_request(request, credentials)
        return security_context
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Authentication service error"
        )


def require_permission(permission: str):
    """Decorator to require specific permissions."""
    def permission_checker(security_context: SecurityContext = Depends(get_current_user)):
        if permission not in security_context.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required"
            )
        return security_context
    
    return permission_checker


def require_resource_access(resource_type: ResourceType, action: str):
    """Decorator to require access to a specific resource type and action."""
    def access_checker(request: Request, security_context: SecurityContext = Depends(get_current_user)):
        # Use the security middleware for authorization
        resource_id = f"{resource_type.value}:{request.url.path}"
        
        try:
            security_middleware.authorize_request(
                security_context=security_context,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action
            )
            return security_context
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            raise HTTPException(
                status_code=500,
                detail="Authorization service error"
            )
    
    return access_checker


# Create a default API key for demo purposes
def create_demo_api_key():
    """Create a demo API key for testing."""
    demo_key = auth_manager.generate_api_key(
        name="demo_key",
        permissions=["query", "admin"]
    )
    
    logger.info(f"Demo API key created: {demo_key['api_key']}")
    return demo_key


# Initialize demo key on module load
DEMO_KEY = create_demo_api_key()