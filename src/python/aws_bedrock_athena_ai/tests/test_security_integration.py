"""
Integration tests for security and compliance features.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from aws_bedrock_athena_ai.security.models import (
    IAMPrincipal, SecurityContext, AccessLevel, 
    DataClassification, AuditEventType
)
from aws_bedrock_athena_ai.security.access_control import ResourceType
from aws_bedrock_athena_ai.security.iam_auth import IAMAuthenticator
from aws_bedrock_athena_ai.security.access_control import AccessController
from aws_bedrock_athena_ai.security.audit_logger import AuditLogger
from aws_bedrock_athena_ai.security.data_redactor import SensitiveDataRedactor
from aws_bedrock_athena_ai.security.monitoring import SecurityMonitor
from aws_bedrock_athena_ai.security.middleware import SecurityMiddleware


class TestSecurityIntegration:
    """Test the integration of security components."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.iam_authenticator = IAMAuthenticator()
        self.audit_logger = AuditLogger()
        self.access_controller = AccessController(self.iam_authenticator, self.audit_logger)
        self.data_redactor = SensitiveDataRedactor()
        self.security_monitor = SecurityMonitor()
        self.security_middleware = SecurityMiddleware()
    
    def test_data_redaction_basic(self):
        """Test basic data redaction functionality."""
        # Test text with sensitive data
        sensitive_text = """
        User email: john.doe@example.com
        Credit card: 4532-1234-5678-9012
        Phone: (555) 123-4567
        IP Address: 192.168.1.100
        """
        
        result = self.data_redactor.redact_text(sensitive_text)
        
        assert result.redacted_text != sensitive_text
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "[CREDIT_CARD_REDACTED]" in result.redacted_text
        assert "[PHONE_REDACTED]" in result.redacted_text
        assert "[IP_REDACTED]" in result.redacted_text
        assert len(result.redactions_made) > 0
    
    def test_data_redaction_structured(self):
        """Test redaction of structured data."""
        sensitive_data = {
            "user_info": {
                "email": "user@example.com",
                "phone": "555-123-4567"
            },
            "logs": [
                "User logged in from 192.168.1.1",
                "API key: sk-1234567890abcdef"
            ]
        }
        
        redacted_data = self.data_redactor.redact_structured_data(sensitive_data)
        
        assert "[EMAIL_REDACTED]" in redacted_data["user_info"]["email"]
        assert "[PHONE_REDACTED]" in redacted_data["user_info"]["phone"]
        assert "[IP_REDACTED]" in redacted_data["logs"][0]
        assert "[API_KEY_REDACTED]" in redacted_data["logs"][1]
    
    def test_security_report_redaction(self):
        """Test redaction of security reports."""
        security_report = {
            "executive_summary": "Detected suspicious login from user@company.com at IP 10.0.0.1",
            "technical_details": {
                "affected_systems": ["server1.company.com", "192.168.1.50"],
                "credentials_found": "AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE"
            },
            "raw_logs": "2024-01-01 10:00:00 - Login attempt from 203.0.113.1 for user john.doe@company.com"
        }
        
        redacted_report = self.data_redactor.redact_security_report(security_report)
        
        # Check that sensitive data is redacted
        assert "[EMAIL_REDACTED]" in redacted_report["executive_summary"]
        assert "[IP_REDACTED]" in redacted_report["executive_summary"]
        assert "[AWS_ACCESS_KEY_REDACTED]" in redacted_report["technical_details"]["credentials_found"]
    
    def test_iam_principal_creation(self):
        """Test IAM principal parsing."""
        # Test assumed role ARN
        arn = "arn:aws:sts::123456789012:assumed-role/SecurityAnalystRole/session-name"
        account_id = "123456789012"
        user_id = "AIDACKCEVSQ6C2EXAMPLE"
        
        principal = self.iam_authenticator._parse_principal_arn(arn, account_id, user_id)
        
        assert principal.principal_type == "assumed-role"
        assert principal.account_id == account_id
        assert principal.role_name == "SecurityAnalystRole"
        assert principal.session_name == "session-name"
    
    def test_access_control_basic(self):
        """Test basic access control functionality."""
        # Create a test principal
        principal = IAMPrincipal(
            principal_type="user",
            principal_id="test-user",
            arn="arn:aws:iam::123456789012:user/test-user",
            account_id="123456789012",
            user_name="test-user"
        )
        
        # Create security context
        security_context = SecurityContext(
            principal=principal,
            access_level=AccessLevel.QUERY,
            permissions=["read", "execute"],
            session_id="test-session",
            request_id="test-request"
        )
        
        # Test authorization for allowed resource
        decision = self.access_controller.authorize_access(
            security_context=security_context,
            resource_type=ResourceType.SECURITY_DATA,
            resource_id="test-data",
            action="read"
        )
        
        assert decision.allowed == True
        assert decision.reason == "Access granted"
    
    def test_audit_logging_events(self):
        """Test audit logging functionality."""
        principal = IAMPrincipal(
            principal_type="user",
            principal_id="test-user",
            arn="arn:aws:iam::123456789012:user/test-user",
            account_id="123456789012"
        )
        
        # Test authentication event logging
        self.audit_logger.log_authentication_event(
            principal=principal,
            success=True,
            source_ip="192.168.1.1"
        )
        
        # Test authorization event logging
        self.audit_logger.log_authorization_event(
            principal=principal,
            resource="test-resource",
            action="read",
            allowed=True,
            required_permissions=["read"]
        )
        
        # Verify statistics are updated
        stats = self.audit_logger.get_audit_statistics()
        assert stats['events_logged'] >= 2
        assert 'authentication' in stats['events_by_type']
        assert 'authorization' in stats['events_by_type']
    
    def test_monitoring_metrics(self):
        """Test security monitoring metrics."""
        # Record authentication events
        self.security_monitor.record_authentication_event(
            success=True,
            principal_type="user",
            source_ip="192.168.1.1"
        )
        
        self.security_monitor.record_authentication_event(
            success=False,
            principal_type="user",
            source_ip="10.0.0.1"
        )
        
        # Record authorization events
        self.security_monitor.record_authorization_event(
            allowed=True,
            resource_type="security_data",
            access_level="query",
            principal_id="test-user"
        )
        
        # Record data access events
        self.security_monitor.record_data_access_event(
            data_source="s3://security-logs",
            records_accessed=100,
            query_type="threat_analysis",
            execution_time_ms=1500.0
        )
        
        # Verify metrics are buffered
        stats = self.security_monitor.get_monitoring_statistics()
        assert stats['metrics_in_buffer'] > 0
    
    @patch('fastapi.Request')
    async def test_security_middleware_integration(self, mock_request):
        """Test the security middleware integration."""
        # Mock request object
        mock_request.headers = {
            'user-agent': 'test-client',
            'x-session-id': 'test-session'
        }
        mock_request.client.host = '192.168.1.1'
        
        # Mock credentials
        from fastapi.security import HTTPAuthorizationCredentials
        mock_credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="test-api-key"
        )
        
        # Mock the API key validation
        with patch('src.python.aws_bedrock_athena_ai.api.auth.auth_manager') as mock_auth_manager:
            mock_auth_manager.validate_api_key.return_value = {
                'key_id': 'test-key',
                'name': 'test-user',
                'permissions': ['query', 'read']
            }
            
            # Test authentication
            security_context = await self.security_middleware.authenticate_request(
                mock_request, mock_credentials
            )
            
            assert security_context is not None
            assert security_context.principal.principal_type == "api_key"
            assert security_context.access_level == AccessLevel.QUERY
    
    def test_redaction_rule_management(self):
        """Test redaction rule management."""
        # Add a custom redaction rule
        self.data_redactor.add_redaction_rule(
            pattern_name="test_pattern",
            pattern_regex=r"TEST-\d{4}",
            replacement="[TEST_ID_REDACTED]",
            data_classification=DataClassification.INTERNAL
        )
        
        # Test the custom rule
        test_text = "Document ID: TEST-1234 was processed"
        result = self.data_redactor.redact_text(test_text)
        
        assert "[TEST_ID_REDACTED]" in result.redacted_text
        assert "TEST-1234" not in result.redacted_text
        
        # Test rule listing
        rules = self.data_redactor.list_rules()
        rule_names = [rule['pattern_name'] for rule in rules]
        assert "test_pattern" in rule_names
        
        # Test rule disabling
        self.data_redactor.disable_rule("test_pattern")
        result2 = self.data_redactor.redact_text(test_text)
        assert "TEST-1234" in result2.redacted_text  # Should not be redacted when disabled
    
    def test_compliance_checks(self):
        """Test compliance checking functionality."""
        principal = IAMPrincipal(
            principal_type="user",
            principal_id="admin-user",
            arn="arn:aws:iam::123456789012:user/admin-user",
            account_id="123456789012"
        )
        
        security_context = SecurityContext(
            principal=principal,
            access_level=AccessLevel.ADMIN,
            permissions=["admin", "read", "write"],
            session_id="admin-session",
            request_id="admin-request",
            mfa_authenticated=False  # This should trigger a compliance issue
        )
        
        # Run compliance checks
        compliance_results = self.access_controller.check_compliance(security_context)
        
        # Should have at least the MFA check
        assert len(compliance_results) > 0
        
        # Find the MFA check
        mfa_check = next((check for check in compliance_results if check.check_name == "admin_mfa_required"), None)
        assert mfa_check is not None
        assert mfa_check.passed == False  # Should fail because MFA is not enabled
        assert mfa_check.severity == "high"
    
    def test_statistics_collection(self):
        """Test that statistics are properly collected across components."""
        # Generate some activity
        principal = IAMPrincipal(
            principal_type="user",
            principal_id="stats-user",
            arn="arn:aws:iam::123456789012:user/stats-user",
            account_id="123456789012"
        )
        
        # Authentication events
        self.audit_logger.log_authentication_event(principal, True)
        self.security_monitor.record_authentication_event(True, "user")
        
        # Data redaction
        self.data_redactor.redact_text("Email: test@example.com")
        
        # Get comprehensive statistics
        stats = self.security_middleware.get_security_statistics()
        
        assert 'access_control' in stats
        assert 'audit_logging' in stats
        assert 'data_redaction' in stats
        assert 'monitoring' in stats
        
        # Verify some statistics are populated
        assert stats['audit_logging']['events_logged'] > 0
        assert stats['data_redaction']['total_redactions'] > 0