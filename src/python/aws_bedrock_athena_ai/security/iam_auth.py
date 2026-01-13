"""
IAM-based authentication and authorization for AWS Bedrock Athena AI.

This module provides integration with AWS IAM for secure authentication
and fine-grained authorization based on IAM policies and roles.
"""

import json
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_bedrock_athena_ai.security.models import IAMPrincipal, AccessRequest, AccessDecision, SecurityContext, AccessLevel

logger = logging.getLogger(__name__)


class IAMAuthenticator:
    """
    Handles IAM-based authentication and authorization.
    
    Integrates with AWS STS to validate credentials and extract principal information,
    then uses IAM policies to make authorization decisions.
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        """Initialize the IAM authenticator."""
        self.region_name = region_name
        self.sts_client = None
        self.iam_client = None
        self._initialize_clients()
        
        # Cache for IAM policy evaluations (5 minute TTL)
        self._policy_cache: Dict[str, Dict] = {}
        self._cache_ttl = 300  # 5 minutes
        
    def _initialize_clients(self):
        """Initialize AWS clients with error handling."""
        try:
            self.sts_client = boto3.client('sts', region_name=self.region_name)
            self.iam_client = boto3.client('iam', region_name=self.region_name)
            logger.info("IAM authenticator initialized successfully")
        except NoCredentialsError:
            logger.warning("No AWS credentials found. IAM authentication will be disabled.")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
    
    def authenticate_request(self, aws_access_key_id: str, aws_secret_access_key: str, 
                           aws_session_token: Optional[str] = None) -> Optional[IAMPrincipal]:
        """
        Authenticate a request using AWS credentials.
        
        Args:
            aws_access_key_id: AWS access key ID
            aws_secret_access_key: AWS secret access key  
            aws_session_token: Optional session token for temporary credentials
            
        Returns:
            IAMPrincipal if authentication succeeds, None otherwise
        """
        if not self.sts_client:
            logger.warning("STS client not available. Skipping IAM authentication.")
            return None
            
        try:
            # Create temporary STS client with provided credentials
            temp_sts = boto3.client(
                'sts',
                region_name=self.region_name,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token
            )
            
            # Get caller identity to validate credentials
            response = temp_sts.get_caller_identity()
            
            # Parse the ARN to extract principal information
            arn = response['Arn']
            account_id = response['Account']
            user_id = response['UserId']
            
            principal = self._parse_principal_arn(arn, account_id, user_id)
            
            logger.info(f"Successfully authenticated principal: {principal.principal_id}")
            return principal
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.warning(f"IAM authentication failed: {error_code}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during IAM authentication: {e}")
            return None
    
    def _parse_principal_arn(self, arn: str, account_id: str, user_id: str) -> IAMPrincipal:
        """Parse an ARN to extract principal information."""
        # ARN format: arn:aws:sts::account:assumed-role/role-name/session-name
        # or: arn:aws:iam::account:user/user-name
        
        parts = arn.split(':')
        if len(parts) < 6:
            raise ValueError(f"Invalid ARN format: {arn}")
        
        resource_part = parts[5]  # The part after the last ':'
        
        if 'assumed-role' in resource_part:
            # Assumed role: assumed-role/role-name/session-name
            _, role_name, session_name = resource_part.split('/', 2)
            return IAMPrincipal(
                principal_type="assumed-role",
                principal_id=user_id,
                arn=arn,
                account_id=account_id,
                role_name=role_name,
                session_name=session_name
            )
        elif 'user/' in resource_part:
            # IAM user: user/user-name
            user_name = resource_part.split('/', 1)[1]
            return IAMPrincipal(
                principal_type="user",
                principal_id=user_id,
                arn=arn,
                account_id=account_id,
                user_name=user_name
            )
        elif 'federated-user/' in resource_part:
            # Federated user
            user_name = resource_part.split('/', 1)[1]
            return IAMPrincipal(
                principal_type="federated-user",
                principal_id=user_id,
                arn=arn,
                account_id=account_id,
                user_name=user_name
            )
        else:
            # Generic principal
            return IAMPrincipal(
                principal_type="unknown",
                principal_id=user_id,
                arn=arn,
                account_id=account_id
            )
    
    def authorize_request(self, access_request: AccessRequest) -> AccessDecision:
        """
        Authorize a request based on IAM policies.
        
        Args:
            access_request: The access request to authorize
            
        Returns:
            AccessDecision with the authorization result
        """
        start_time = datetime.utcnow()
        
        try:
            # Check cache first
            cache_key = self._get_cache_key(access_request)
            cached_decision = self._get_cached_decision(cache_key)
            if cached_decision:
                logger.debug(f"Using cached authorization decision for {access_request.principal.principal_id}")
                return cached_decision
            
            # Evaluate IAM policies
            decision = self._evaluate_iam_policies(access_request)
            
            # Cache the decision
            self._cache_decision(cache_key, decision)
            
            decision.decision_time = datetime.utcnow()
            
            logger.info(f"Authorization decision for {access_request.principal.principal_id}: "
                       f"{'ALLOWED' if decision.allowed else 'DENIED'}")
            
            return decision
            
        except Exception as e:
            logger.error(f"Error during authorization: {e}")
            return AccessDecision(
                allowed=False,
                reason=f"Authorization error: {str(e)}",
                required_permissions=[],
                missing_permissions=[],
                conditions_met=False,
                decision_time=datetime.utcnow()
            )
    
    def _evaluate_iam_policies(self, access_request: AccessRequest) -> AccessDecision:
        """Evaluate IAM policies for the access request."""
        if not self.iam_client:
            # Fallback to basic permission checking if IAM client not available
            return self._evaluate_basic_permissions(access_request)
        
        try:
            # Use IAM policy simulator for accurate policy evaluation
            response = self.iam_client.simulate_principal_policy(
                PolicySourceArn=access_request.principal.arn,
                ActionNames=[access_request.action],
                ResourceArns=[access_request.resource],
                ContextEntries=[
                    {
                        'ContextKeyName': 'aws:RequestedRegion',
                        'ContextKeyValues': [self.region_name],
                        'ContextKeyType': 'string'
                    },
                    {
                        'ContextKeyName': 'aws:SourceIp',
                        'ContextKeyValues': [access_request.source_ip or '0.0.0.0'],
                        'ContextKeyType': 'ipAddress'
                    }
                ]
            )
            
            # Parse simulation results
            evaluation_results = response.get('EvaluationResults', [])
            if not evaluation_results:
                return AccessDecision(
                    allowed=False,
                    reason="No policy evaluation results",
                    required_permissions=[access_request.action],
                    missing_permissions=[access_request.action],
                    conditions_met=False,
                    decision_time=datetime.utcnow()
                )
            
            result = evaluation_results[0]
            decision = result['EvalDecision']
            
            if decision == 'allowed':
                return AccessDecision(
                    allowed=True,
                    reason="Access granted by IAM policy",
                    required_permissions=[access_request.action],
                    missing_permissions=[],
                    conditions_met=True,
                    decision_time=datetime.utcnow()
                )
            else:
                # Extract details about why access was denied
                matched_statements = result.get('MatchedStatements', [])
                missing_context = result.get('MissingContextValues', [])
                
                reason = f"Access denied: {decision}"
                if matched_statements:
                    reason += f" (matched {len(matched_statements)} policy statements)"
                if missing_context:
                    reason += f" (missing context: {', '.join(missing_context)})"
                
                return AccessDecision(
                    allowed=False,
                    reason=reason,
                    required_permissions=[access_request.action],
                    missing_permissions=[access_request.action],
                    conditions_met=len(missing_context) == 0,
                    decision_time=datetime.utcnow()
                )
                
        except ClientError as e:
            logger.warning(f"IAM policy simulation failed: {e}")
            return self._evaluate_basic_permissions(access_request)
        except Exception as e:
            logger.error(f"Unexpected error during policy evaluation: {e}")
            return AccessDecision(
                allowed=False,
                reason=f"Policy evaluation error: {str(e)}",
                required_permissions=[access_request.action],
                missing_permissions=[access_request.action],
                conditions_met=False,
                decision_time=datetime.utcnow()
            )
    
    def _evaluate_basic_permissions(self, access_request: AccessRequest) -> AccessDecision:
        """Fallback permission evaluation when IAM client is not available."""
        # Basic permission mapping for common actions
        action_permissions = {
            "bedrock:InvokeModel": ["bedrock:InvokeModel"],
            "athena:StartQueryExecution": ["athena:StartQueryExecution", "s3:GetObject"],
            "athena:GetQueryResults": ["athena:GetQueryResults"],
            "s3:GetObject": ["s3:GetObject"],
            "s3:ListBucket": ["s3:ListBucket"],
            "logs:CreateLogGroup": ["logs:CreateLogGroup"],
            "logs:CreateLogStream": ["logs:CreateLogStream"],
            "logs:PutLogEvents": ["logs:PutLogEvents"]
        }
        
        required_permissions = action_permissions.get(access_request.action, [access_request.action])
        
        # For basic evaluation, assume access is allowed if principal has a valid ARN
        # In production, this would check against a local policy store
        if access_request.principal.arn and access_request.principal.account_id:
            return AccessDecision(
                allowed=True,
                reason="Basic permission check passed",
                required_permissions=required_permissions,
                missing_permissions=[],
                conditions_met=True,
                decision_time=datetime.utcnow()
            )
        else:
            return AccessDecision(
                allowed=False,
                reason="Invalid principal",
                required_permissions=required_permissions,
                missing_permissions=required_permissions,
                conditions_met=False,
                decision_time=datetime.utcnow()
            )
    
    def _get_cache_key(self, access_request: AccessRequest) -> str:
        """Generate a cache key for the access request."""
        return f"{access_request.principal.arn}:{access_request.action}:{access_request.resource}"
    
    def _get_cached_decision(self, cache_key: str) -> Optional[AccessDecision]:
        """Get a cached authorization decision if still valid."""
        if cache_key in self._policy_cache:
            cached_entry = self._policy_cache[cache_key]
            if datetime.utcnow() - cached_entry['timestamp'] < timedelta(seconds=self._cache_ttl):
                return cached_entry['decision']
            else:
                # Remove expired entry
                del self._policy_cache[cache_key]
        return None
    
    def _cache_decision(self, cache_key: str, decision: AccessDecision):
        """Cache an authorization decision."""
        self._policy_cache[cache_key] = {
            'decision': decision,
            'timestamp': datetime.utcnow()
        }
        
        # Clean up old cache entries periodically
        if len(self._policy_cache) > 1000:
            self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Remove expired entries from the cache."""
        current_time = datetime.utcnow()
        expired_keys = [
            key for key, entry in self._policy_cache.items()
            if current_time - entry['timestamp'] > timedelta(seconds=self._cache_ttl)
        ]
        
        for key in expired_keys:
            del self._policy_cache[key]
        
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def create_security_context(self, principal: IAMPrincipal, session_id: str, 
                              request_id: str, **kwargs) -> SecurityContext:
        """Create a security context for a validated principal."""
        # Determine access level based on principal type and policies
        access_level = self._determine_access_level(principal)
        
        # Extract permissions from IAM policies (simplified for demo)
        permissions = self._extract_permissions(principal)
        
        return SecurityContext(
            principal=principal,
            access_level=access_level,
            permissions=permissions,
            session_id=session_id,
            request_id=request_id,
            source_ip=kwargs.get('source_ip'),
            user_agent=kwargs.get('user_agent'),
            mfa_authenticated=kwargs.get('mfa_authenticated', False),
            session_duration=kwargs.get('session_duration')
        )
    
    def _determine_access_level(self, principal: IAMPrincipal) -> AccessLevel:
        """Determine the access level for a principal."""
        # Simplified logic - in production, this would analyze IAM policies
        if principal.role_name and 'admin' in principal.role_name.lower():
            return AccessLevel.ADMIN
        elif principal.role_name and 'audit' in principal.role_name.lower():
            return AccessLevel.AUDIT
        elif principal.principal_type == "user":
            return AccessLevel.QUERY
        else:
            return AccessLevel.READ_ONLY
    
    def _extract_permissions(self, principal: IAMPrincipal) -> List[str]:
        """Extract permissions for a principal."""
        # Simplified permission extraction - in production, this would
        # analyze attached IAM policies and extract specific permissions
        base_permissions = ["bedrock:InvokeModel", "athena:StartQueryExecution"]
        
        if principal.role_name and 'admin' in principal.role_name.lower():
            base_permissions.extend([
                "iam:ListUsers", "iam:ListRoles", "s3:ListAllMyBuckets",
                "logs:CreateLogGroup", "cloudwatch:PutMetricData"
            ])
        
        return base_permissions