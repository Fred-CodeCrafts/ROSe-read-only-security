"""
Security middleware for AI Security Analyst API.

This module provides integrated security middleware that combines
authentication, authorization, audit logging, data redaction,
and monitoring into a cohesive security layer.
"""

import uuid
import logging
from typing import Optional, Dict, Any, Callable
from datetime import datetime
from fastapi import Request, Response, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from aws_bedrock_athena_ai.security.models import SecurityContext, AccessLevel, ResourceType
from aws_bedrock_athena_ai.security.iam_auth import IAMAuthenticator
from aws_bedrock_athena_ai.security.access_control import AccessController
from aws_bedrock_athena_ai.security.audit_logger import AuditLogger
from aws_bedrock_athena_ai.security.data_redactor import SensitiveDataRedactor
from aws_bedrock_athena_ai.security.monitoring import SecurityMonitor

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Integrated security middleware for the AI Security Analyst API.
    
    Provides a unified security layer that handles authentication,
    authorization, audit logging, data redaction, and monitoring.
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        """Initialize the security middleware."""
        self.region_name = region_name
        
        # Initialize security components
        self.iam_authenticator = IAMAuthenticator(region_name)
        self.audit_logger = AuditLogger(region_name=region_name)
        self.access_controller = AccessController(self.iam_authenticator, self.audit_logger)
        self.data_redactor = SensitiveDataRedactor()
        self.security_monitor = SecurityMonitor(region_name)
        
        # HTTP Bearer token handler
        self.security_scheme = HTTPBearer()
        
        # Request tracking
        self.active_requests: Dict[str, SecurityContext] = {}
        
        logger.info("Security middleware initialized successfully")
    
    async def authenticate_request(self, request: Request, 
                                 credentials: Optional[HTTPAuthorizationCredentials] = None) -> SecurityContext:
        """
        Authenticate an incoming request and create a security context.
        
        Args:
            request: FastAPI request object
            credentials: Optional HTTP bearer credentials
            
        Returns:
            SecurityContext for the authenticated request
            
        Raises:
            HTTPException: If authentication fails
        """
        request_id = str(uuid.uuid4())
        session_id = self._extract_session_id(request)
        source_ip = self._extract_source_ip(request)
        user_agent = request.headers.get('user-agent')
        
        try:
            # Extract AWS credentials from request
            aws_credentials = self._extract_aws_credentials(request, credentials)
            
            if aws_credentials:
                # Authenticate using IAM
                principal = self.iam_authenticator.authenticate_request(
                    aws_access_key_id=aws_credentials['access_key_id'],
                    aws_secret_access_key=aws_credentials['secret_access_key'],
                    aws_session_token=aws_credentials.get('session_token')
                )
                
                if not principal:
                    # Log authentication failure
                    self.security_monitor.record_authentication_event(
                        success=False,
                        principal_type="unknown",
                        source_ip=source_ip
                    )
                    
                    raise HTTPException(
                        status_code=401,
                        detail="Invalid AWS credentials"
                    )
                
                # Create security context
                security_context = self.access_controller.create_security_context(
                    principal=principal,
                    session_id=session_id,
                    request_id=request_id,
                    source_ip=source_ip,
                    user_agent=user_agent
                )
                
                # Log successful authentication
                self.audit_logger.log_authentication_event(
                    principal=principal,
                    success=True,
                    source_ip=source_ip,
                    user_agent=user_agent
                )
                
                self.security_monitor.record_authentication_event(
                    success=True,
                    principal_type=principal.principal_type,
                    source_ip=source_ip
                )
                
            else:
                # Fallback to API key authentication for demo purposes
                security_context = self._authenticate_with_api_key(
                    request, credentials, request_id, session_id, source_ip, user_agent
                )
            
            # Track the request
            self.active_requests[request_id] = security_context
            
            return security_context
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            
            # Log error event
            self.audit_logger.log_error_event(
                security_context=None,
                error_type="authentication_error",
                error_message=str(e)
            )
            
            self.security_monitor.record_error_event(
                error_type="authentication_error",
                component="security_middleware"
            )
            
            raise HTTPException(
                status_code=500,
                detail="Authentication service error"
            )
    
    def authorize_request(self, security_context: SecurityContext,
                         resource_type: ResourceType, resource_id: str,
                         action: str, **kwargs) -> bool:
        """
        Authorize a request for a specific resource and action.
        
        Args:
            security_context: The security context of the request
            resource_type: Type of resource being accessed
            resource_id: Specific resource identifier
            action: The action being performed
            **kwargs: Additional context for authorization
            
        Returns:
            True if authorized, False otherwise
            
        Raises:
            HTTPException: If authorization fails
        """
        try:
            # Perform authorization check
            decision = self.access_controller.authorize_access(
                security_context=security_context,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                **kwargs
            )
            
            # Record monitoring metrics
            self.security_monitor.record_authorization_event(
                allowed=decision.allowed,
                resource_type=resource_type.value,
                access_level=security_context.access_level.value,
                principal_id=security_context.principal.principal_id
            )
            
            if not decision.allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied: {decision.reason}",
                    headers={
                        "X-Required-Permissions": ",".join(decision.required_permissions),
                        "X-Missing-Permissions": ",".join(decision.missing_permissions)
                    }
                )
            
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            
            # Log error event
            self.audit_logger.log_error_event(
                security_context=security_context,
                error_type="authorization_error",
                error_message=str(e)
            )
            
            self.security_monitor.record_error_event(
                error_type="authorization_error",
                component="security_middleware"
            )
            
            raise HTTPException(
                status_code=500,
                detail="Authorization service error"
            )
    
    def log_data_access(self, security_context: SecurityContext,
                       data_source: str, query: str, records_accessed: int = 0,
                       execution_time_ms: float = 0.0, **kwargs):
        """Log a data access event."""
        try:
            # Log audit event
            self.audit_logger.log_data_access_event(
                security_context=security_context,
                data_source=data_source,
                query=query,
                records_accessed=records_accessed,
                details=kwargs
            )
            
            # Record monitoring metrics
            self.security_monitor.record_data_access_event(
                data_source=data_source,
                records_accessed=records_accessed,
                query_type=kwargs.get('query_type', 'unknown'),
                execution_time_ms=execution_time_ms
            )
            
        except Exception as e:
            logger.error(f"Failed to log data access event: {e}")
    
    def log_analysis_request(self, security_context: SecurityContext,
                           analysis_type: str, question: str,
                           threats_found: int = 0, risk_score: Optional[float] = None,
                           processing_time_ms: Optional[float] = None, **kwargs):
        """Log an AI analysis request event."""
        try:
            # Log audit event
            self.audit_logger.log_analysis_request_event(
                security_context=security_context,
                analysis_type=analysis_type,
                question=question,
                threats_found=threats_found,
                risk_score=risk_score,
                processing_time_ms=processing_time_ms,
                details=kwargs
            )
            
            # Record monitoring metrics
            self.security_monitor.record_analysis_request_event(
                analysis_type=analysis_type,
                processing_time_ms=processing_time_ms or 0.0,
                threats_found=threats_found,
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"Failed to log analysis request event: {e}")
    
    def redact_response_data(self, data: Any, security_context: SecurityContext) -> Any:
        """
        Redact sensitive data from response based on user's access level.
        
        Args:
            data: The response data to redact
            security_context: The security context of the request
            
        Returns:
            Redacted response data
        """
        try:
            # Determine redaction level based on access level
            classification_level = None
            if security_context.access_level == AccessLevel.READ_ONLY:
                from aws_bedrock_athena_ai.security.models import DataClassification
                classification_level = DataClassification.INTERNAL
            elif security_context.access_level == AccessLevel.QUERY:
                from aws_bedrock_athena_ai.security.models import DataClassification
                classification_level = DataClassification.CONFIDENTIAL
            # Admin and Audit users get full access
            
            if isinstance(data, str):
                result = self.data_redactor.redact_text(data, classification_level)
                return result.redacted_text
            elif isinstance(data, dict):
                if 'executive_summary' in data or 'technical_details' in data:
                    # This looks like a security report
                    return self.data_redactor.redact_security_report(data)
                else:
                    return self.data_redactor.redact_structured_data(data, classification_level)
            else:
                return data
                
        except Exception as e:
            logger.error(f"Failed to redact response data: {e}")
            return data  # Return original data if redaction fails
    
    def cleanup_request(self, request_id: str):
        """Clean up resources for a completed request."""
        if request_id in self.active_requests:
            del self.active_requests[request_id]
    
    def _extract_session_id(self, request: Request) -> str:
        """Extract or generate a session ID from the request."""
        # Try to get session ID from headers
        session_id = request.headers.get('x-session-id')
        if not session_id:
            # Try to get from cookies
            session_id = request.cookies.get('session_id')
        if not session_id:
            # Generate a new session ID
            session_id = str(uuid.uuid4())
        return session_id
    
    def _extract_source_ip(self, request: Request) -> Optional[str]:
        """Extract the source IP address from the request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fallback to client host
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return None
    
    def _extract_aws_credentials(self, request: Request, 
                                credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[Dict[str, str]]:
        """Extract AWS credentials from the request."""
        # Method 1: From Authorization header (custom format)
        if credentials and credentials.scheme.lower() == 'aws':
            # Expected format: "AWS access_key_id:secret_access_key:session_token"
            try:
                parts = credentials.credentials.split(':')
                if len(parts) >= 2:
                    result = {
                        'access_key_id': parts[0],
                        'secret_access_key': parts[1]
                    }
                    if len(parts) > 2:
                        result['session_token'] = parts[2]
                    return result
            except Exception:
                pass
        
        # Method 2: From custom headers
        access_key = request.headers.get('x-aws-access-key-id')
        secret_key = request.headers.get('x-aws-secret-access-key')
        session_token = request.headers.get('x-aws-session-token')
        
        if access_key and secret_key:
            result = {
                'access_key_id': access_key,
                'secret_access_key': secret_key
            }
            if session_token:
                result['session_token'] = session_token
            return result
        
        # Method 3: From environment (for local development)
        # This would be handled by boto3 automatically
        
        return None
    
    def _authenticate_with_api_key(self, request: Request, 
                                 credentials: Optional[HTTPAuthorizationCredentials],
                                 request_id: str, session_id: str, 
                                 source_ip: Optional[str], user_agent: Optional[str]) -> SecurityContext:
        """Fallback authentication using API keys."""
        from aws_bedrock_athena_ai.api.auth import auth_manager
        from aws_bedrock_athena_ai.security.models import IAMPrincipal
        
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Missing authentication credentials"
            )
        
        # Validate API key
        key_data = auth_manager.validate_api_key(credentials.credentials)
        if not key_data:
            self.security_monitor.record_authentication_event(
                success=False,
                principal_type="api_key",
                source_ip=source_ip
            )
            
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )
        
        # Create a pseudo-IAM principal for API key users
        principal = IAMPrincipal(
            principal_type="api_key",
            principal_id=key_data['key_id'],
            arn=f"arn:aws:iam::demo:api-key/{key_data['key_id']}",
            account_id="demo",
            user_name=key_data['name']
        )
        
        # Determine access level based on permissions
        access_level = AccessLevel.READ_ONLY
        if 'admin' in key_data.get('permissions', []):
            access_level = AccessLevel.ADMIN
        elif 'query' in key_data.get('permissions', []):
            access_level = AccessLevel.QUERY
        
        # Create security context
        security_context = SecurityContext(
            principal=principal,
            access_level=access_level,
            permissions=key_data.get('permissions', []),
            session_id=session_id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        # Log successful authentication
        self.audit_logger.log_authentication_event(
            principal=principal,
            success=True,
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        self.security_monitor.record_authentication_event(
            success=True,
            principal_type="api_key",
            source_ip=source_ip
        )
        
        return security_context
    
    def get_security_statistics(self) -> Dict[str, Any]:
        """Get comprehensive security statistics."""
        return {
            'active_requests': len(self.active_requests),
            'access_control': self.access_controller.get_access_statistics(),
            'audit_logging': self.audit_logger.get_audit_statistics(),
            'data_redaction': self.data_redactor.get_redaction_statistics(),
            'monitoring': self.security_monitor.get_monitoring_statistics()
        }
    
    def flush_all_logs_and_metrics(self):
        """Flush all pending logs and metrics."""
        try:
            self.audit_logger.flush_all_logs()
            self.security_monitor.flush_all_metrics()
        except Exception as e:
            logger.error(f"Failed to flush logs and metrics: {e}")


# Global security middleware instance
security_middleware = SecurityMiddleware()