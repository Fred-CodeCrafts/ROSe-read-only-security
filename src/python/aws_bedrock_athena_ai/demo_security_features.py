#!/usr/bin/env python3
"""
Demo script showing the security and compliance features.

This script demonstrates the key security capabilities including:
- Data redaction
- Audit logging
- Access control
- Monitoring metrics
"""

import asyncio
import json
from datetime import datetime

from security.models import (
    IAMPrincipal, SecurityContext, AccessLevel, DataClassification
)
from security.access_control import ResourceType
from security.data_redactor import SensitiveDataRedactor
from security.audit_logger import AuditLogger
from security.monitoring import SecurityMonitor
from security.access_control import AccessController
from security.iam_auth import IAMAuthenticator


def demo_data_redaction():
    """Demonstrate data redaction capabilities."""
    print("=" * 60)
    print("DATA REDACTION DEMO")
    print("=" * 60)
    
    redactor = SensitiveDataRedactor()
    
    # Test various types of sensitive data
    sensitive_data = """
    Security Analysis Report
    
    User Information:
    - Email: john.doe@company.com
    - Phone: (555) 123-4567
    - Credit Card: 4532-1234-5678-9012
    
    System Information:
    - Server IP: 192.168.1.100
    - Database IP: 10.0.0.50
    - API Key: sk-1234567890abcdef
    - AWS Access Key: AKIAIOSFODNN7EXAMPLE
    
    Log Entries:
    - 2024-01-01 10:00:00 - Login from 203.0.113.1 for user admin@company.com
    - 2024-01-01 10:05:00 - Password reset for SSN: 123-45-6789
    """
    
    print("Original Data:")
    print(sensitive_data)
    print("\n" + "-" * 40 + "\n")
    
    # Redact the data
    result = redactor.redact_text(sensitive_data)
    
    print("Redacted Data:")
    print(result.redacted_text)
    print("\n" + "-" * 40 + "\n")
    
    print(f"Redactions Made: {len(result.redactions_made)}")
    print(f"Classification Level: {result.classification_level.value}")
    print(f"Processing Time: {result.processing_time_ms:.2f}ms")
    
    # Show redaction statistics
    stats = redactor.get_redaction_statistics()
    print(f"\nRedaction Statistics:")
    print(f"- Total redactions: {stats['total_redactions']}")
    print(f"- Active rules: {stats['active_rules']}")
    print(f"- Redactions by type: {stats['redactions_by_type']}")


def demo_structured_data_redaction():
    """Demonstrate structured data redaction."""
    print("\n" + "=" * 60)
    print("STRUCTURED DATA REDACTION DEMO")
    print("=" * 60)
    
    redactor = SensitiveDataRedactor()
    
    # Security report with sensitive data
    security_report = {
        "executive_summary": "Detected suspicious activity from user admin@company.com accessing sensitive data from IP 192.168.1.100",
        "technical_details": {
            "affected_users": ["john.doe@company.com", "jane.smith@company.com"],
            "source_ips": ["192.168.1.100", "10.0.0.50"],
            "credentials_found": "AWS Access Key: AKIAIOSFODNN7EXAMPLE found in logs"
        },
        "recommendations": [
            "Reset password for user admin@company.com",
            "Block IP address 192.168.1.100",
            "Rotate API key sk-1234567890abcdef"
        ]
    }
    
    print("Original Security Report:")
    print(json.dumps(security_report, indent=2))
    
    # Redact the security report
    redacted_report = redactor.redact_security_report(security_report)
    
    print("\nRedacted Security Report:")
    print(json.dumps(redacted_report, indent=2))


def demo_audit_logging():
    """Demonstrate audit logging capabilities."""
    print("\n" + "=" * 60)
    print("AUDIT LOGGING DEMO")
    print("=" * 60)
    
    audit_logger = AuditLogger()
    
    # Create a test principal
    principal = IAMPrincipal(
        principal_type="user",
        principal_id="demo-user-123",
        arn="arn:aws:iam::123456789012:user/demo-user",
        account_id="123456789012",
        user_name="demo-user"
    )
    
    # Create security context
    security_context = SecurityContext(
        principal=principal,
        access_level=AccessLevel.QUERY,
        permissions=["read", "execute"],
        session_id="demo-session-456",
        request_id="demo-request-789",
        source_ip="192.168.1.100"
    )
    
    print("Logging various security events...")
    
    # Log authentication event
    audit_logger.log_authentication_event(
        principal=principal,
        success=True,
        source_ip="192.168.1.100",
        details={"login_method": "api_key"}
    )
    
    # Log authorization event
    audit_logger.log_authorization_event(
        principal=principal,
        resource="security-data-bucket",
        action="read",
        allowed=True,
        required_permissions=["s3:GetObject"]
    )
    
    # Log data access event
    audit_logger.log_data_access_event(
        security_context=security_context,
        data_source="s3://security-logs/2024/01/",
        query="SELECT * FROM security_events WHERE timestamp > '2024-01-01'",
        records_accessed=150
    )
    
    # Log analysis request
    audit_logger.log_analysis_request_event(
        security_context=security_context,
        analysis_type="threat_detection",
        question="Are there any suspicious login patterns?",
        threats_found=2,
        risk_score=7.5,
        processing_time_ms=2500.0
    )
    
    # Get audit statistics
    stats = audit_logger.get_audit_statistics()
    print(f"\nAudit Statistics:")
    print(f"- Events logged: {stats['events_logged']}")
    print(f"- Events by type: {stats['events_by_type']}")
    print(f"- Failed logs: {stats['failed_logs']}")
    print(f"- Log group: {stats['log_group']}")


def demo_access_control():
    """Demonstrate access control capabilities."""
    print("\n" + "=" * 60)
    print("ACCESS CONTROL DEMO")
    print("=" * 60)
    
    # Initialize components
    iam_authenticator = IAMAuthenticator()
    audit_logger = AuditLogger()
    access_controller = AccessController(iam_authenticator, audit_logger)
    
    # Create different types of principals
    admin_principal = IAMPrincipal(
        principal_type="assumed-role",
        principal_id="admin-role-123",
        arn="arn:aws:sts::123456789012:assumed-role/SecurityAdminRole/admin-session",
        account_id="123456789012",
        role_name="SecurityAdminRole",
        session_name="admin-session"
    )
    
    query_principal = IAMPrincipal(
        principal_type="user",
        principal_id="query-user-456",
        arn="arn:aws:iam::123456789012:user/query-user",
        account_id="123456789012",
        user_name="query-user"
    )
    
    # Create security contexts
    admin_context = SecurityContext(
        principal=admin_principal,
        access_level=AccessLevel.ADMIN,
        permissions=["admin", "read", "write", "execute"],
        session_id="admin-session",
        request_id="admin-request"
    )
    
    query_context = SecurityContext(
        principal=query_principal,
        access_level=AccessLevel.QUERY,
        permissions=["read", "execute"],
        session_id="query-session",
        request_id="query-request"
    )
    
    # Test different access scenarios
    test_scenarios = [
        (admin_context, ResourceType.CONFIGURATION, "config-settings", "modify"),
        (query_context, ResourceType.CONFIGURATION, "config-settings", "modify"),
        (admin_context, ResourceType.SECURITY_DATA, "threat-logs", "read"),
        (query_context, ResourceType.SECURITY_DATA, "threat-logs", "read"),
        (admin_context, ResourceType.AUDIT_LOGS, "access-logs", "read"),
        (query_context, ResourceType.AUDIT_LOGS, "access-logs", "read"),
    ]
    
    print("Testing access control scenarios:")
    print("-" * 40)
    
    for context, resource_type, resource_id, action in test_scenarios:
        decision = access_controller.authorize_access(
            security_context=context,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action
        )
        
        status = "ALLOWED" if decision.allowed else "DENIED"
        user_type = context.access_level.value
        
        print(f"{user_type:10} | {resource_type.value:15} | {action:8} | {status}")
        if not decision.allowed:
            print(f"           Reason: {decision.reason}")
    
    # Show access statistics
    stats = access_controller.get_access_statistics()
    print(f"\nAccess Control Statistics:")
    print(f"- Total requests: {stats['total_requests']}")
    print(f"- Allowed: {stats['allowed_requests']}")
    print(f"- Denied: {stats['denied_requests']}")
    print(f"- Success rate: {stats['success_rate']:.1f}%")


def demo_monitoring():
    """Demonstrate monitoring capabilities."""
    print("\n" + "=" * 60)
    print("MONITORING DEMO")
    print("=" * 60)
    
    monitor = SecurityMonitor()
    
    print("Recording various security metrics...")
    
    # Record authentication events
    monitor.record_authentication_event(True, "user", "192.168.1.100")
    monitor.record_authentication_event(False, "user", "10.0.0.1")
    monitor.record_authentication_event(True, "assumed-role", "192.168.1.101")
    
    # Record authorization events
    monitor.record_authorization_event(True, "security_data", "query", "user-123")
    monitor.record_authorization_event(False, "configuration", "admin", "user-456")
    
    # Record data access events
    monitor.record_data_access_event(
        data_source="s3://security-logs",
        records_accessed=250,
        query_type="threat_analysis",
        execution_time_ms=1800.0
    )
    
    # Record analysis requests
    monitor.record_analysis_request_event(
        analysis_type="threat_detection",
        processing_time_ms=3200.0,
        threats_found=3,
        risk_score=8.2
    )
    
    # Record cost metrics
    monitor.record_cost_metric("bedrock", 0.05, "text_generation")
    monitor.record_cost_metric("athena", 0.02, "query_execution")
    
    # Record compliance metrics
    monitor.record_compliance_metric("mfa_required", True, "high")
    monitor.record_compliance_metric("session_timeout", False, "medium")
    
    # Get monitoring statistics
    stats = monitor.get_monitoring_statistics()
    print(f"\nMonitoring Statistics:")
    print(f"- Metrics in buffer: {stats['metrics_in_buffer']}")
    print(f"- Namespace: {stats['namespace']}")
    print(f"- CloudWatch available: {stats['cloudwatch_available']}")
    
    print("\nSample metrics recorded:")
    print("- Authentication events (success/failure)")
    print("- Authorization decisions")
    print("- Data access patterns")
    print("- Analysis processing times")
    print("- Cost tracking")
    print("- Compliance status")


def main():
    """Run all security feature demos."""
    print("AI Security Analyst - Security Features Demo")
    print("=" * 60)
    
    try:
        # Run all demos
        demo_data_redaction()
        demo_structured_data_redaction()
        demo_audit_logging()
        demo_access_control()
        demo_monitoring()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nKey Security Features Demonstrated:")
        print("✓ Sensitive data redaction with configurable rules")
        print("✓ Comprehensive audit logging for compliance")
        print("✓ Role-based access control with IAM integration")
        print("✓ CloudWatch monitoring and metrics")
        print("✓ Security context management")
        print("✓ Compliance checking and reporting")
        
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()