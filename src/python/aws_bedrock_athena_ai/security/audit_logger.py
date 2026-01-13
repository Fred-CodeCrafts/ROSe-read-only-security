"""
Comprehensive audit logging for AI Security Analyst.

This module provides detailed audit logging capabilities that track all
security-related operations, data access, and analysis requests for
compliance and security monitoring purposes.
"""

import json
import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

from aws_bedrock_athena_ai.security.models import AuditEvent, AuditEventType, IAMPrincipal, SecurityContext

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Comprehensive audit logging system for security and compliance.
    
    Logs all security-related operations to CloudWatch Logs and optionally
    to S3 for long-term retention and compliance requirements.
    """
    
    def __init__(self, log_group_name: str = "/aws/bedrock-athena-ai/audit",
                 region_name: str = "us-east-1", s3_bucket: Optional[str] = None):
        """
        Initialize the audit logger.
        
        Args:
            log_group_name: CloudWatch log group name
            region_name: AWS region
            s3_bucket: Optional S3 bucket for long-term log retention
        """
        self.log_group_name = log_group_name
        self.region_name = region_name
        self.s3_bucket = s3_bucket
        
        # Initialize AWS clients
        self.cloudwatch_logs = None
        self.s3_client = None
        self._initialize_clients()
        
        # Create log stream name with timestamp
        self.log_stream_name = f"audit-{datetime.utcnow().strftime('%Y-%m-%d-%H')}"
        
        # Ensure log group and stream exist
        self._ensure_log_infrastructure()
        
        # In-memory buffer for batch logging
        self._log_buffer: List[Dict[str, Any]] = []
        self._buffer_size = 100
        
        # Statistics
        self.audit_stats = {
            'events_logged': 0,
            'events_by_type': {},
            'failed_logs': 0,
            'last_log_time': None
        }
    
    def _initialize_clients(self):
        """Initialize AWS clients with error handling."""
        try:
            self.cloudwatch_logs = boto3.client('logs', region_name=self.region_name)
            if self.s3_bucket:
                self.s3_client = boto3.client('s3', region_name=self.region_name)
            logger.info("Audit logger AWS clients initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients for audit logging: {e}")
    
    def _ensure_log_infrastructure(self):
        """Ensure CloudWatch log group and stream exist."""
        if not self.cloudwatch_logs:
            logger.warning("CloudWatch Logs client not available. Audit logs will be local only.")
            return
        
        try:
            # Create log group if it doesn't exist
            try:
                self.cloudwatch_logs.create_log_group(logGroupName=self.log_group_name)
                logger.info(f"Created CloudWatch log group: {self.log_group_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Create log stream if it doesn't exist
            try:
                self.cloudwatch_logs.create_log_stream(
                    logGroupName=self.log_group_name,
                    logStreamName=self.log_stream_name
                )
                logger.info(f"Created CloudWatch log stream: {self.log_stream_name}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
                    
        except Exception as e:
            logger.error(f"Failed to ensure log infrastructure: {e}")
    
    def log_authentication_event(self, principal: IAMPrincipal, success: bool,
                                source_ip: Optional[str] = None, 
                                user_agent: Optional[str] = None,
                                details: Optional[Dict[str, Any]] = None):
        """Log an authentication event."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.AUTHENTICATION,
            timestamp=datetime.now(timezone.utc),
            principal=principal,
            resource="authentication",
            action="authenticate",
            result="success" if success else "failure",
            details=details or {},
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        self._log_event(event)
    
    def log_authorization_event(self, principal: IAMPrincipal, resource: str, 
                              action: str, allowed: bool,
                              required_permissions: List[str],
                              source_ip: Optional[str] = None,
                              details: Optional[Dict[str, Any]] = None):
        """Log an authorization event."""
        event_details = {
            'required_permissions': required_permissions,
            'authorization_result': 'allowed' if allowed else 'denied'
        }
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.AUTHORIZATION,
            timestamp=datetime.now(timezone.utc),
            principal=principal,
            resource=resource,
            action=action,
            result="success" if allowed else "failure",
            details=event_details,
            source_ip=source_ip
        )
        
        self._log_event(event)
    
    def log_data_access_event(self, security_context: SecurityContext, 
                            data_source: str, query: str,
                            records_accessed: int = 0,
                            data_classification: str = "internal",
                            details: Optional[Dict[str, Any]] = None):
        """Log a data access event."""
        event_details = {
            'data_source': data_source,
            'query_hash': self._hash_query(query),
            'records_accessed': records_accessed,
            'data_classification': data_classification,
            'session_id': security_context.session_id,
            'request_id': security_context.request_id
        }
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.DATA_ACCESS,
            timestamp=datetime.now(timezone.utc),
            principal=security_context.principal,
            resource=data_source,
            action="data_access",
            result="success",
            details=event_details,
            source_ip=security_context.source_ip,
            user_agent=security_context.user_agent,
            session_id=security_context.session_id,
            request_id=security_context.request_id
        )
        
        self._log_event(event)
    
    def log_query_execution_event(self, security_context: SecurityContext,
                                query_type: str, query: str, 
                                execution_time_ms: float,
                                records_returned: int = 0,
                                cost_estimate: Optional[float] = None,
                                details: Optional[Dict[str, Any]] = None):
        """Log a query execution event."""
        event_details = {
            'query_type': query_type,
            'query_hash': self._hash_query(query),
            'execution_time_ms': execution_time_ms,
            'records_returned': records_returned,
            'session_id': security_context.session_id,
            'request_id': security_context.request_id
        }
        
        if cost_estimate is not None:
            event_details['cost_estimate_usd'] = cost_estimate
        
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.QUERY_EXECUTION,
            timestamp=datetime.now(timezone.utc),
            principal=security_context.principal,
            resource="athena_query",
            action="execute_query",
            result="success",
            details=event_details,
            source_ip=security_context.source_ip,
            user_agent=security_context.user_agent,
            session_id=security_context.session_id,
            request_id=security_context.request_id
        )
        
        self._log_event(event)
    
    def log_analysis_request_event(self, security_context: SecurityContext,
                                 analysis_type: str, question: str,
                                 threats_found: int = 0,
                                 risk_score: Optional[float] = None,
                                 processing_time_ms: Optional[float] = None,
                                 details: Optional[Dict[str, Any]] = None):
        """Log an AI analysis request event."""
        event_details = {
            'analysis_type': analysis_type,
            'question_hash': self._hash_query(question),
            'threats_found': threats_found,
            'session_id': security_context.session_id,
            'request_id': security_context.request_id
        }
        
        if risk_score is not None:
            event_details['risk_score'] = risk_score
        
        if processing_time_ms is not None:
            event_details['processing_time_ms'] = processing_time_ms
        
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.ANALYSIS_REQUEST,
            timestamp=datetime.now(timezone.utc),
            principal=security_context.principal,
            resource="ai_analysis",
            action="analyze_security",
            result="success",
            details=event_details,
            source_ip=security_context.source_ip,
            user_agent=security_context.user_agent,
            session_id=security_context.session_id,
            request_id=security_context.request_id
        )
        
        self._log_event(event)
    
    def log_configuration_change_event(self, security_context: SecurityContext,
                                     configuration_type: str, 
                                     old_value: Any, new_value: Any,
                                     details: Optional[Dict[str, Any]] = None):
        """Log a configuration change event."""
        event_details = {
            'configuration_type': configuration_type,
            'old_value_hash': self._hash_value(str(old_value)),
            'new_value_hash': self._hash_value(str(new_value)),
            'session_id': security_context.session_id,
            'request_id': security_context.request_id
        }
        
        if details:
            event_details.update(details)
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            timestamp=datetime.now(timezone.utc),
            principal=security_context.principal,
            resource="configuration",
            action="modify_configuration",
            result="success",
            details=event_details,
            source_ip=security_context.source_ip,
            user_agent=security_context.user_agent,
            session_id=security_context.session_id,
            request_id=security_context.request_id
        )
        
        self._log_event(event)
    
    def log_error_event(self, security_context: Optional[SecurityContext],
                       error_type: str, error_message: str,
                       stack_trace: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None):
        """Log an error event."""
        event_details = {
            'error_type': error_type,
            'error_message': error_message
        }
        
        if stack_trace:
            event_details['stack_trace_hash'] = self._hash_value(stack_trace)
        
        if security_context:
            event_details.update({
                'session_id': security_context.session_id,
                'request_id': security_context.request_id
            })
        
        if details:
            event_details.update(details)
        
        # Create a minimal principal if none provided
        principal = security_context.principal if security_context else IAMPrincipal(
            principal_type="system",
            principal_id="system",
            arn="arn:aws:iam::000000000000:root",
            account_id="000000000000"
        )
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.ERROR,
            timestamp=datetime.now(timezone.utc),
            principal=principal,
            resource="system",
            action="error_occurred",
            result="error",
            details=event_details,
            source_ip=security_context.source_ip if security_context else None,
            user_agent=security_context.user_agent if security_context else None,
            session_id=security_context.session_id if security_context else None,
            request_id=security_context.request_id if security_context else None
        )
        
        self._log_event(event)
    
    def _log_event(self, event: AuditEvent):
        """Log an audit event to all configured destinations."""
        try:
            # Convert event to JSON
            event_json = self._serialize_event(event)
            
            # Add to buffer for batch processing
            self._log_buffer.append(event_json)
            
            # Update statistics
            self.audit_stats['events_logged'] += 1
            self.audit_stats['events_by_type'][event.event_type.value] = \
                self.audit_stats['events_by_type'].get(event.event_type.value, 0) + 1
            self.audit_stats['last_log_time'] = datetime.now(timezone.utc)
            
            # Flush buffer if it's full
            if len(self._log_buffer) >= self._buffer_size:
                self._flush_log_buffer()
            
            # Also log to Python logger for immediate visibility
            log_level = logging.WARNING if event.result in ['failure', 'error'] else logging.INFO
            logger.log(log_level, f"AUDIT: {event.event_type.value} - {event.action} - {event.result}")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            self.audit_stats['failed_logs'] += 1
    
    def _serialize_event(self, event: AuditEvent) -> Dict[str, Any]:
        """Serialize an audit event to JSON-compatible format."""
        return {
            'event_id': event.event_id,
            'event_type': event.event_type.value,
            'timestamp': event.timestamp.isoformat(),
            'principal': {
                'type': event.principal.principal_type,
                'id': event.principal.principal_id,
                'arn': event.principal.arn,
                'account_id': event.principal.account_id,
                'user_name': event.principal.user_name,
                'role_name': event.principal.role_name,
                'session_name': event.principal.session_name
            },
            'resource': event.resource,
            'action': event.action,
            'result': event.result,
            'details': event.details,
            'source_ip': event.source_ip,
            'user_agent': event.user_agent,
            'session_id': event.session_id,
            'request_id': event.request_id
        }
    
    def _flush_log_buffer(self):
        """Flush the log buffer to CloudWatch Logs."""
        if not self._log_buffer or not self.cloudwatch_logs:
            return
        
        try:
            # Prepare log events for CloudWatch
            log_events = [
                {
                    'timestamp': int(datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp() * 1000),
                    'message': json.dumps(event, separators=(',', ':'))
                }
                for event in self._log_buffer
            ]
            
            # Sort by timestamp (required by CloudWatch)
            log_events.sort(key=lambda x: x['timestamp'])
            
            # Send to CloudWatch Logs
            self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=log_events
            )
            
            logger.debug(f"Flushed {len(log_events)} audit events to CloudWatch Logs")
            
            # Optionally archive to S3
            if self.s3_bucket:
                self._archive_to_s3(self._log_buffer)
            
            # Clear the buffer
            self._log_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to flush audit log buffer: {e}")
            self.audit_stats['failed_logs'] += len(self._log_buffer)
    
    def _archive_to_s3(self, events: List[Dict[str, Any]]):
        """Archive audit events to S3 for long-term retention."""
        if not self.s3_client or not events:
            return
        
        try:
            # Create S3 key with date partitioning
            now = datetime.now(timezone.utc)
            s3_key = f"audit-logs/year={now.year}/month={now.month:02d}/day={now.day:02d}/hour={now.hour:02d}/{uuid.uuid4()}.json"
            
            # Prepare the data
            archive_data = {
                'metadata': {
                    'archive_timestamp': now.isoformat(),
                    'event_count': len(events),
                    'log_group': self.log_group_name,
                    'log_stream': self.log_stream_name
                },
                'events': events
            }
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=json.dumps(archive_data, separators=(',', ':')),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.debug(f"Archived {len(events)} audit events to S3: s3://{self.s3_bucket}/{s3_key}")
            
        except Exception as e:
            logger.error(f"Failed to archive audit events to S3: {e}")
    
    def _hash_query(self, query: str) -> str:
        """Create a hash of a query for audit logging (to avoid logging sensitive data)."""
        import hashlib
        return hashlib.sha256(query.encode()).hexdigest()[:16]
    
    def _hash_value(self, value: str) -> str:
        """Create a hash of a value for audit logging."""
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()[:16]
    
    def flush_all_logs(self):
        """Manually flush all pending logs."""
        if self._log_buffer:
            self._flush_log_buffer()
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics."""
        return {
            'events_logged': self.audit_stats['events_logged'],
            'events_by_type': dict(self.audit_stats['events_by_type']),
            'failed_logs': self.audit_stats['failed_logs'],
            'last_log_time': self.audit_stats['last_log_time'].isoformat() if self.audit_stats['last_log_time'] else None,
            'buffer_size': len(self._log_buffer),
            'log_group': self.log_group_name,
            'log_stream': self.log_stream_name,
            's3_archiving': self.s3_bucket is not None
        }