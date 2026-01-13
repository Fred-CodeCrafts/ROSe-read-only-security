"""
CloudWatch monitoring and alerting for AI Security Analyst.

This module provides comprehensive monitoring capabilities including
custom metrics, alarms, and dashboards for security and compliance monitoring.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

from aws_bedrock_athena_ai.security.models import SecurityContext, AuditEventType

logger = logging.getLogger(__name__)


class SecurityMonitor:
    """
    CloudWatch monitoring and alerting for security events.
    
    Provides custom metrics, alarms, and dashboards for monitoring
    security-related activities and compliance status.
    """
    
    def __init__(self, region_name: str = "us-east-1", 
                 namespace: str = "AWS/BedrockAthenaAI/Security"):
        """
        Initialize the security monitor.
        
        Args:
            region_name: AWS region
            namespace: CloudWatch namespace for custom metrics
        """
        self.region_name = region_name
        self.namespace = namespace
        
        # Initialize AWS clients
        self.cloudwatch = None
        self.sns = None
        self._initialize_clients()
        
        # Metric tracking
        self.metrics_buffer: List[Dict[str, Any]] = []
        self.buffer_size = 50
        
        # Alarm configurations
        self.alarm_configs = self._initialize_alarm_configs()
        
    def _initialize_clients(self):
        """Initialize AWS clients with error handling."""
        try:
            self.cloudwatch = boto3.client('cloudwatch', region_name=self.region_name)
            self.sns = boto3.client('sns', region_name=self.region_name)
            logger.info("Security monitor AWS clients initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients for monitoring: {e}")
    
    def _initialize_alarm_configs(self) -> Dict[str, Dict[str, Any]]:
        """Initialize default alarm configurations."""
        return {
            'authentication_failures': {
                'metric_name': 'AuthenticationFailures',
                'threshold': 10,
                'period': 300,  # 5 minutes
                'evaluation_periods': 2,
                'comparison_operator': 'GreaterThanThreshold',
                'description': 'High number of authentication failures detected'
            },
            'authorization_denials': {
                'metric_name': 'AuthorizationDenials',
                'threshold': 20,
                'period': 300,
                'evaluation_periods': 2,
                'comparison_operator': 'GreaterThanThreshold',
                'description': 'High number of authorization denials detected'
            },
            'data_access_anomalies': {
                'metric_name': 'DataAccessRate',
                'threshold': 1000,
                'period': 3600,  # 1 hour
                'evaluation_periods': 1,
                'comparison_operator': 'GreaterThanThreshold',
                'description': 'Unusual data access patterns detected'
            },
            'error_rate': {
                'metric_name': 'ErrorRate',
                'threshold': 5,  # 5% error rate
                'period': 300,
                'evaluation_periods': 3,
                'comparison_operator': 'GreaterThanThreshold',
                'description': 'High error rate detected'
            },
            'cost_anomalies': {
                'metric_name': 'CostPerHour',
                'threshold': 10.0,  # $10 per hour
                'period': 3600,
                'evaluation_periods': 1,
                'comparison_operator': 'GreaterThanThreshold',
                'description': 'Unusual cost patterns detected'
            }
        }
    
    def record_authentication_event(self, success: bool, principal_type: str,
                                  source_ip: Optional[str] = None):
        """Record an authentication event metric."""
        metric_name = "AuthenticationSuccesses" if success else "AuthenticationFailures"
        
        dimensions = [
            {'Name': 'PrincipalType', 'Value': principal_type}
        ]
        
        if source_ip:
            # Anonymize IP for privacy (keep first 3 octets)
            ip_parts = source_ip.split('.')
            if len(ip_parts) == 4:
                anonymized_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.xxx"
                dimensions.append({'Name': 'SourceIPRange', 'Value': anonymized_ip})
        
        self._add_metric(
            metric_name=metric_name,
            value=1,
            unit='Count',
            dimensions=dimensions
        )
    
    def record_authorization_event(self, allowed: bool, resource_type: str,
                                 access_level: str, principal_id: str):
        """Record an authorization event metric."""
        metric_name = "AuthorizationSuccesses" if allowed else "AuthorizationDenials"
        
        dimensions = [
            {'Name': 'ResourceType', 'Value': resource_type},
            {'Name': 'AccessLevel', 'Value': access_level}
        ]
        
        self._add_metric(
            metric_name=metric_name,
            value=1,
            unit='Count',
            dimensions=dimensions
        )
        
        # Track unique principals for anomaly detection
        self._add_metric(
            metric_name="UniquePrincipals",
            value=1,
            unit='Count',
            dimensions=[{'Name': 'PrincipalId', 'Value': principal_id[:8]}]  # Truncated for privacy
        )
    
    def record_data_access_event(self, data_source: str, records_accessed: int,
                               query_type: str, execution_time_ms: float):
        """Record a data access event metric."""
        dimensions = [
            {'Name': 'DataSource', 'Value': data_source},
            {'Name': 'QueryType', 'Value': query_type}
        ]
        
        # Record access count
        self._add_metric(
            metric_name="DataAccessCount",
            value=records_accessed,
            unit='Count',
            dimensions=dimensions
        )
        
        # Record query performance
        self._add_metric(
            metric_name="QueryExecutionTime",
            value=execution_time_ms,
            unit='Milliseconds',
            dimensions=dimensions
        )
        
        # Calculate and record data access rate
        self._add_metric(
            metric_name="DataAccessRate",
            value=1,
            unit='Count/Second',
            dimensions=dimensions
        )
    
    def record_analysis_request_event(self, analysis_type: str, processing_time_ms: float,
                                    threats_found: int, risk_score: Optional[float] = None):
        """Record an AI analysis request event metric."""
        dimensions = [
            {'Name': 'AnalysisType', 'Value': analysis_type}
        ]
        
        # Record processing time
        self._add_metric(
            metric_name="AnalysisProcessingTime",
            value=processing_time_ms,
            unit='Milliseconds',
            dimensions=dimensions
        )
        
        # Record threats found
        self._add_metric(
            metric_name="ThreatsDetected",
            value=threats_found,
            unit='Count',
            dimensions=dimensions
        )
        
        # Record risk score if available
        if risk_score is not None:
            self._add_metric(
                metric_name="RiskScore",
                value=risk_score,
                unit='None',
                dimensions=dimensions
            )
        
        # Track analysis request rate
        self._add_metric(
            metric_name="AnalysisRequestRate",
            value=1,
            unit='Count/Second',
            dimensions=dimensions
        )
    
    def record_error_event(self, error_type: str, component: str):
        """Record an error event metric."""
        dimensions = [
            {'Name': 'ErrorType', 'Value': error_type},
            {'Name': 'Component', 'Value': component}
        ]
        
        self._add_metric(
            metric_name="Errors",
            value=1,
            unit='Count',
            dimensions=dimensions
        )
        
        # Calculate error rate
        self._add_metric(
            metric_name="ErrorRate",
            value=1,
            unit='Percent',
            dimensions=dimensions
        )
    
    def record_cost_metric(self, service: str, cost_usd: float, operation_type: str):
        """Record cost-related metrics."""
        dimensions = [
            {'Name': 'Service', 'Value': service},
            {'Name': 'OperationType', 'Value': operation_type}
        ]
        
        self._add_metric(
            metric_name="CostPerOperation",
            value=cost_usd,
            unit='None',
            dimensions=dimensions
        )
        
        # Track hourly cost accumulation
        self._add_metric(
            metric_name="CostPerHour",
            value=cost_usd,
            unit='None',
            dimensions=dimensions
        )
    
    def record_compliance_metric(self, check_name: str, passed: bool, severity: str):
        """Record compliance check metrics."""
        dimensions = [
            {'Name': 'CheckName', 'Value': check_name},
            {'Name': 'Severity', 'Value': severity}
        ]
        
        metric_name = "ComplianceChecksPassed" if passed else "ComplianceChecksFailed"
        
        self._add_metric(
            metric_name=metric_name,
            value=1,
            unit='Count',
            dimensions=dimensions
        )
        
        # Calculate compliance score
        compliance_score = 100 if passed else 0
        self._add_metric(
            metric_name="ComplianceScore",
            value=compliance_score,
            unit='Percent',
            dimensions=dimensions
        )
    
    def _add_metric(self, metric_name: str, value: float, unit: str,
                   dimensions: List[Dict[str, str]]):
        """Add a metric to the buffer for batch sending."""
        metric_data = {
            'MetricName': metric_name,
            'Value': value,
            'Unit': unit,
            'Dimensions': dimensions,
            'Timestamp': datetime.now(timezone.utc)
        }
        
        self.metrics_buffer.append(metric_data)
        
        # Flush buffer if it's full
        if len(self.metrics_buffer) >= self.buffer_size:
            self._flush_metrics()
    
    def _flush_metrics(self):
        """Flush metrics buffer to CloudWatch."""
        if not self.metrics_buffer or not self.cloudwatch:
            return
        
        try:
            # CloudWatch accepts max 20 metrics per request
            batch_size = 20
            
            for i in range(0, len(self.metrics_buffer), batch_size):
                batch = self.metrics_buffer[i:i + batch_size]
                
                self.cloudwatch.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=batch
                )
            
            logger.debug(f"Flushed {len(self.metrics_buffer)} metrics to CloudWatch")
            self.metrics_buffer.clear()
            
        except Exception as e:
            logger.error(f"Failed to flush metrics to CloudWatch: {e}")
    
    def create_security_dashboard(self, dashboard_name: str = "AI-Security-Analyst-Dashboard"):
        """Create a CloudWatch dashboard for security monitoring."""
        if not self.cloudwatch:
            logger.warning("CloudWatch client not available. Cannot create dashboard.")
            return
        
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0, "y": 0, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "AuthenticationSuccesses"],
                            [self.namespace, "AuthenticationFailures"]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": self.region_name,
                        "title": "Authentication Events"
                    }
                },
                {
                    "type": "metric",
                    "x": 12, "y": 0, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "AuthorizationSuccesses"],
                            [self.namespace, "AuthorizationDenials"]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": self.region_name,
                        "title": "Authorization Events"
                    }
                },
                {
                    "type": "metric",
                    "x": 0, "y": 6, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "DataAccessCount"],
                            [self.namespace, "QueryExecutionTime"]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": self.region_name,
                        "title": "Data Access Metrics"
                    }
                },
                {
                    "type": "metric",
                    "x": 12, "y": 6, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "ThreatsDetected"],
                            [self.namespace, "RiskScore"]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": self.region_name,
                        "title": "Threat Analysis Metrics"
                    }
                },
                {
                    "type": "metric",
                    "x": 0, "y": 12, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "Errors"],
                            [self.namespace, "ErrorRate"]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": self.region_name,
                        "title": "Error Metrics"
                    }
                },
                {
                    "type": "metric",
                    "x": 12, "y": 12, "width": 12, "height": 6,
                    "properties": {
                        "metrics": [
                            [self.namespace, "CostPerHour"],
                            [self.namespace, "ComplianceScore"]
                        ],
                        "period": 3600,
                        "stat": "Average",
                        "region": self.region_name,
                        "title": "Cost and Compliance"
                    }
                }
            ]
        }
        
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            logger.info(f"Created CloudWatch dashboard: {dashboard_name}")
        except Exception as e:
            logger.error(f"Failed to create CloudWatch dashboard: {e}")
    
    def create_security_alarms(self, sns_topic_arn: Optional[str] = None):
        """Create CloudWatch alarms for security monitoring."""
        if not self.cloudwatch:
            logger.warning("CloudWatch client not available. Cannot create alarms.")
            return
        
        alarm_actions = [sns_topic_arn] if sns_topic_arn else []
        
        for alarm_name, config in self.alarm_configs.items():
            try:
                self.cloudwatch.put_metric_alarm(
                    AlarmName=f"AI-Security-Analyst-{alarm_name}",
                    ComparisonOperator=config['comparison_operator'],
                    EvaluationPeriods=config['evaluation_periods'],
                    MetricName=config['metric_name'],
                    Namespace=self.namespace,
                    Period=config['period'],
                    Statistic='Sum',
                    Threshold=config['threshold'],
                    ActionsEnabled=True,
                    AlarmActions=alarm_actions,
                    AlarmDescription=config['description'],
                    Unit='Count'
                )
                logger.info(f"Created CloudWatch alarm: AI-Security-Analyst-{alarm_name}")
            except Exception as e:
                logger.error(f"Failed to create alarm {alarm_name}: {e}")
    
    def flush_all_metrics(self):
        """Manually flush all pending metrics."""
        if self.metrics_buffer:
            self._flush_metrics()
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            'metrics_in_buffer': len(self.metrics_buffer),
            'namespace': self.namespace,
            'region': self.region_name,
            'alarm_count': len(self.alarm_configs),
            'cloudwatch_available': self.cloudwatch is not None
        }