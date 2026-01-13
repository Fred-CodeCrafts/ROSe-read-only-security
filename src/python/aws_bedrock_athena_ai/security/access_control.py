"""
Access control and authorization management for AI Security Analyst.

This module provides comprehensive access control capabilities including
role-based access control (RBAC), resource-level permissions, and
integration with IAM for fine-grained authorization decisions.
"""

import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
from enum import Enum

from aws_bedrock_athena_ai.security.models import (
    AccessLevel, SecurityContext, AccessRequest, AccessDecision, 
    IAMPrincipal, ComplianceCheck
)
from aws_bedrock_athena_ai.security.iam_auth import IAMAuthenticator
from aws_bedrock_athena_ai.security.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of resources that can be accessed."""
    SECURITY_DATA = "security_data"
    ANALYSIS_RESULTS = "analysis_results"
    CONFIGURATION = "configuration"
    AUDIT_LOGS = "audit_logs"
    API_ENDPOINTS = "api_endpoints"
    REPORTS = "reports"


class Permission(Enum):
    """Granular permissions for different operations."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    AUDIT = "audit"


class AccessController:
    """
    Comprehensive access control system for the AI Security Analyst.
    
    Provides role-based access control, resource-level permissions,
    and integration with IAM for enterprise-grade security.
    """
    
    def __init__(self, iam_authenticator: IAMAuthenticator, 
                 audit_logger: AuditLogger):
        """
        Initialize the access controller.
        
        Args:
            iam_authenticator: IAM authenticator instance
            audit_logger: Audit logger instance
        """
        self.iam_authenticator = iam_authenticator
        self.audit_logger = audit_logger
        
        # Define role-based permissions
        self._role_permissions = self._initialize_role_permissions()
        
        # Resource-specific access rules
        self._resource_rules = self._initialize_resource_rules()
        
        # Session tracking
        self._active_sessions: Dict[str, SecurityContext] = {}
        self._session_timeout = timedelta(hours=8)  # 8-hour session timeout
        
        # Access statistics
        self.access_stats = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'requests_by_resource': {},
            'requests_by_principal': {}
        }
    
    def _initialize_role_permissions(self) -> Dict[AccessLevel, Set[Permission]]:
        """Initialize default role-based permissions."""
        return {
            AccessLevel.READ_ONLY: {
                Permission.READ
            },
            AccessLevel.QUERY: {
                Permission.READ,
                Permission.EXECUTE
            },
            AccessLevel.ADMIN: {
                Permission.READ,
                Permission.WRITE,
                Permission.DELETE,
                Permission.EXECUTE,
                Permission.ADMIN
            },
            AccessLevel.AUDIT: {
                Permission.READ,
                Permission.AUDIT
            }
        }
    
    def _initialize_resource_rules(self) -> Dict[ResourceType, Dict[str, Any]]:
        """Initialize resource-specific access rules."""
        return {
            ResourceType.SECURITY_DATA: {
                'required_permissions': [Permission.READ],
                'classification_required': True,
                'audit_required': True,
                'rate_limit': 1000  # requests per hour
            },
            ResourceType.ANALYSIS_RESULTS: {
                'required_permissions': [Permission.READ],
                'classification_required': False,
                'audit_required': True,
                'rate_limit': 500
            },
            ResourceType.CONFIGURATION: {
                'required_permissions': [Permission.ADMIN],
                'classification_required': False,
                'audit_required': True,
                'rate_limit': 100
            },
            ResourceType.AUDIT_LOGS: {
                'required_permissions': [Permission.AUDIT],
                'classification_required': True,
                'audit_required': True,
                'rate_limit': 200
            },
            ResourceType.API_ENDPOINTS: {
                'required_permissions': [Permission.EXECUTE],
                'classification_required': False,
                'audit_required': True,
                'rate_limit': 2000
            },
            ResourceType.REPORTS: {
                'required_permissions': [Permission.READ],
                'classification_required': False,
                'audit_required': True,
                'rate_limit': 300
            }
        }
    
    def authorize_access(self, security_context: SecurityContext, 
                        resource_type: ResourceType, resource_id: str,
                        action: str, **kwargs) -> AccessDecision:
        """
        Authorize access to a resource based on security context and policies.
        
        Args:
            security_context: The security context of the request
            resource_type: Type of resource being accessed
            resource_id: Specific resource identifier
            action: The action being performed
            **kwargs: Additional context for authorization
            
        Returns:
            AccessDecision with the authorization result
        """
        start_time = datetime.utcnow()
        
        # Update statistics
        self.access_stats['total_requests'] += 1
        self.access_stats['requests_by_resource'][resource_type.value] = \
            self.access_stats['requests_by_resource'].get(resource_type.value, 0) + 1
        self.access_stats['requests_by_principal'][security_context.principal.principal_id] = \
            self.access_stats['requests_by_principal'].get(security_context.principal.principal_id, 0) + 1
        
        try:
            # Check session validity
            if not self._is_session_valid(security_context):
                decision = AccessDecision(
                    allowed=False,
                    reason="Session expired or invalid",
                    required_permissions=[],
                    missing_permissions=[],
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
                self._log_authorization_event(security_context, resource_id, action, decision)
                return decision
            
            # Get resource rules
            resource_rules = self._resource_rules.get(resource_type)
            if not resource_rules:
                decision = AccessDecision(
                    allowed=False,
                    reason=f"No access rules defined for resource type: {resource_type.value}",
                    required_permissions=[],
                    missing_permissions=[],
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
                self._log_authorization_event(security_context, resource_id, action, decision)
                return decision
            
            # Check role-based permissions
            role_permissions = self._role_permissions.get(security_context.access_level, set())
            required_permissions = resource_rules['required_permissions']
            
            missing_permissions = []
            for required_perm in required_permissions:
                if required_perm not in role_permissions:
                    missing_permissions.append(required_perm.value)
            
            if missing_permissions:
                decision = AccessDecision(
                    allowed=False,
                    reason=f"Insufficient permissions. Missing: {', '.join(missing_permissions)}",
                    required_permissions=[p.value for p in required_permissions],
                    missing_permissions=missing_permissions,
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
                self._log_authorization_event(security_context, resource_id, action, decision)
                return decision
            
            # Check rate limits
            if not self._check_rate_limit(security_context, resource_type):
                decision = AccessDecision(
                    allowed=False,
                    reason="Rate limit exceeded for resource type",
                    required_permissions=[p.value for p in required_permissions],
                    missing_permissions=[],
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
                self._log_authorization_event(security_context, resource_id, action, decision)
                return decision
            
            # Check additional conditions
            conditions_met = self._check_additional_conditions(
                security_context, resource_type, resource_id, action, **kwargs
            )
            
            if not conditions_met['passed']:
                decision = AccessDecision(
                    allowed=False,
                    reason=f"Additional conditions not met: {conditions_met['reason']}",
                    required_permissions=[p.value for p in required_permissions],
                    missing_permissions=[],
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
                self._log_authorization_event(security_context, resource_id, action, decision)
                return decision
            
            # If we get here, access is allowed
            decision = AccessDecision(
                allowed=True,
                reason="Access granted",
                required_permissions=[p.value for p in required_permissions],
                missing_permissions=[],
                conditions_met=True,
                decision_time=datetime.utcnow()
            )
            
            # Update statistics
            self.access_stats['allowed_requests'] += 1
            
            # Log the authorization event
            self._log_authorization_event(security_context, resource_id, action, decision)
            
            return decision
            
        except Exception as e:
            logger.error(f"Error during access authorization: {e}")
            decision = AccessDecision(
                allowed=False,
                reason=f"Authorization error: {str(e)}",
                required_permissions=[],
                missing_permissions=[],
                conditions_met=False,
                decision_time=datetime.utcnow()
            )
            
            self.access_stats['denied_requests'] += 1
            self._log_authorization_event(security_context, resource_id, action, decision)
            return decision
    
    def _is_session_valid(self, security_context: SecurityContext) -> bool:
        """Check if a security context session is still valid."""
        session_id = security_context.session_id
        
        # Check if session exists and is not expired
        if session_id in self._active_sessions:
            stored_context = self._active_sessions[session_id]
            # Simple session validation - in production, this would be more sophisticated
            return True
        
        # For new sessions, add to tracking
        self._active_sessions[security_context.session_id] = security_context
        return True
    
    def _check_rate_limit(self, security_context: SecurityContext, 
                         resource_type: ResourceType) -> bool:
        """Check if the request is within rate limits."""
        # Simplified rate limiting - in production, this would use a proper rate limiter
        # like Redis or DynamoDB with sliding windows
        
        resource_rules = self._resource_rules.get(resource_type)
        if not resource_rules:
            return True
        
        rate_limit = resource_rules.get('rate_limit', 1000)
        
        # For demo purposes, always allow access
        # In production, implement proper rate limiting logic
        return True
    
    def _check_additional_conditions(self, security_context: SecurityContext,
                                   resource_type: ResourceType, resource_id: str,
                                   action: str, **kwargs) -> Dict[str, Any]:
        """Check additional conditions for resource access."""
        
        # Time-based access restrictions
        current_hour = datetime.utcnow().hour
        if resource_type == ResourceType.CONFIGURATION and current_hour < 6:
            return {
                'passed': False,
                'reason': 'Configuration changes not allowed during maintenance window (0-6 UTC)'
            }
        
        # Data classification requirements
        resource_rules = self._resource_rules.get(resource_type, {})
        if resource_rules.get('classification_required'):
            data_classification = kwargs.get('data_classification', 'internal')
            if data_classification == 'restricted' and security_context.access_level != AccessLevel.ADMIN:
                return {
                    'passed': False,
                    'reason': 'Admin access required for restricted data'
                }
        
        # MFA requirements for sensitive operations
        if action in ['delete', 'modify_configuration'] and not security_context.mfa_authenticated:
            return {
                'passed': False,
                'reason': 'Multi-factor authentication required for sensitive operations'
            }
        
        # Source IP restrictions (example)
        if security_context.source_ip:
            # In production, check against allowed IP ranges
            pass
        
        return {'passed': True, 'reason': 'All conditions met'}
    
    def _log_authorization_event(self, security_context: SecurityContext,
                               resource_id: str, action: str, 
                               decision: AccessDecision):
        """Log an authorization event for audit purposes."""
        try:
            self.audit_logger.log_authorization_event(
                principal=security_context.principal,
                resource=resource_id,
                action=action,
                allowed=decision.allowed,
                required_permissions=decision.required_permissions,
                source_ip=security_context.source_ip,
                details={
                    'access_level': security_context.access_level.value,
                    'session_id': security_context.session_id,
                    'request_id': security_context.request_id,
                    'decision_reason': decision.reason,
                    'conditions_met': decision.conditions_met
                }
            )
        except Exception as e:
            logger.error(f"Failed to log authorization event: {e}")
    
    def create_security_context(self, principal: IAMPrincipal, session_id: str,
                              request_id: str, **kwargs) -> SecurityContext:
        """Create a security context using the IAM authenticator."""
        return self.iam_authenticator.create_security_context(
            principal=principal,
            session_id=session_id,
            request_id=request_id,
            **kwargs
        )
    
    def invalidate_session(self, session_id: str):
        """Invalidate a security session."""
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]
            logger.info(f"Invalidated session: {session_id}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, context in self._active_sessions.items():
            # Simple expiration check - in production, track session creation time
            # For now, just clean up sessions older than timeout
            expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def check_compliance(self, security_context: SecurityContext) -> List[ComplianceCheck]:
        """
        Perform compliance checks for the current security context.
        
        Returns:
            List of compliance check results
        """
        checks = []
        
        # Check 1: MFA requirement for admin operations
        if security_context.access_level == AccessLevel.ADMIN:
            checks.append(ComplianceCheck(
                check_name="admin_mfa_required",
                passed=security_context.mfa_authenticated,
                details="Admin users must use multi-factor authentication",
                recommendations=["Enable MFA for admin account"] if not security_context.mfa_authenticated else [],
                severity="high" if not security_context.mfa_authenticated else "low",
                timestamp=datetime.utcnow()
            ))
        
        # Check 2: Session duration limits
        max_session_duration = 28800  # 8 hours in seconds
        current_duration = security_context.session_duration or 0
        
        checks.append(ComplianceCheck(
            check_name="session_duration_limit",
            passed=current_duration <= max_session_duration,
            details=f"Session duration: {current_duration}s (max: {max_session_duration}s)",
            recommendations=["Refresh session"] if current_duration > max_session_duration else [],
            severity="medium" if current_duration > max_session_duration else "low",
            timestamp=datetime.utcnow()
        ))
        
        # Check 3: Principle of least privilege
        excessive_permissions = self._check_excessive_permissions(security_context)
        checks.append(ComplianceCheck(
            check_name="least_privilege",
            passed=len(excessive_permissions) == 0,
            details=f"Excessive permissions detected: {', '.join(excessive_permissions)}",
            recommendations=[f"Remove permission: {perm}" for perm in excessive_permissions],
            severity="medium" if excessive_permissions else "low",
            timestamp=datetime.utcnow()
        ))
        
        return checks
    
    def _check_excessive_permissions(self, security_context: SecurityContext) -> List[str]:
        """Check for excessive permissions that violate least privilege principle."""
        excessive = []
        
        # Example: Users with admin access but only using read operations
        if (security_context.access_level == AccessLevel.ADMIN and 
            len(security_context.permissions) > 10):
            excessive.append("admin_overprovisioned")
        
        return excessive
    
    def get_access_statistics(self) -> Dict[str, Any]:
        """Get access control statistics."""
        return {
            'total_requests': self.access_stats['total_requests'],
            'allowed_requests': self.access_stats['allowed_requests'],
            'denied_requests': self.access_stats['denied_requests'],
            'success_rate': (
                self.access_stats['allowed_requests'] / max(1, self.access_stats['total_requests'])
            ) * 100,
            'requests_by_resource': dict(self.access_stats['requests_by_resource']),
            'requests_by_principal': dict(self.access_stats['requests_by_principal']),
            'active_sessions': len(self._active_sessions)
        }
    
    def get_resource_permissions(self, resource_type: ResourceType) -> Dict[str, Any]:
        """Get permission requirements for a resource type."""
        rules = self._resource_rules.get(resource_type, {})
        return {
            'resource_type': resource_type.value,
            'required_permissions': [p.value for p in rules.get('required_permissions', [])],
            'classification_required': rules.get('classification_required', False),
            'audit_required': rules.get('audit_required', False),
            'rate_limit': rules.get('rate_limit', 0)
        }