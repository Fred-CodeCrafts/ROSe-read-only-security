"""
Sample data generator for onboarding and demonstrations.

This module creates realistic security data samples that can be used
for immediate analysis and demonstration purposes.
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

from aws_bedrock_athena_ai.onboarding.models import DataFormat

logger = logging.getLogger(__name__)


class SampleDataGenerator:
    """Generates realistic sample security data for demonstrations"""
    
    def __init__(self):
        # Sample data pools for realistic generation
        self.sample_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.1.50", "10.0.1.51", "10.0.2.100",
            "203.0.113.50", "198.51.100.25", "203.0.113.75"  # Suspicious external IPs
        ]
        
        self.sample_users = [
            "john.doe", "jane.smith", "admin", "service_account",
            "backup_user", "monitoring", "alice.johnson", "bob.wilson"
        ]
        
        self.sample_events = [
            "UserLogin", "UserLogout", "FileAccess", "AdminAction",
            "SystemStart", "SystemShutdown", "NetworkConnection",
            "PasswordChange", "PermissionChange", "DataExport"
        ]
        
        self.sample_systems = [
            "web-server-01", "db-server-01", "app-server-01",
            "firewall-01", "router-01", "workstation-01"
        ]
        
        self.suspicious_patterns = {
            "failed_logins": ["admin", "administrator", "root"],
            "suspicious_ips": ["203.0.113.50", "198.51.100.25"],
            "off_hours": [22, 23, 0, 1, 2, 3, 4, 5],  # 10 PM to 5 AM
            "suspicious_events": ["AdminAction", "PermissionChange", "DataExport"]
        }
    
    def generate_sample_dataset(self, 
                              format_type: DataFormat = DataFormat.JSON,
                              record_count: int = 1000,
                              include_threats: bool = True) -> str:
        """
        Generate a complete sample security dataset.
        
        Args:
            format_type: Format to generate (JSON, CSV, etc.)
            record_count: Number of records to generate
            include_threats: Whether to include suspicious activities
            
        Returns:
            String containing the generated dataset
        """
        logger.info(f"🔧 Generating {record_count} sample records in {format_type.value} format")
        
        if format_type == DataFormat.JSON:
            return self._generate_json_logs(record_count, include_threats)
        elif format_type == DataFormat.CSV:
            return self._generate_csv_logs(record_count, include_threats)
        elif format_type == DataFormat.CLOUDTRAIL:
            return self._generate_cloudtrail_logs(record_count, include_threats)
        elif format_type == DataFormat.SYSLOG:
            return self._generate_syslog_logs(record_count, include_threats)
        elif format_type == DataFormat.VPC_FLOW:
            return self._generate_vpc_flow_logs(record_count, include_threats)
        else:
            return self._generate_json_logs(record_count, include_threats)
    
    def _generate_json_logs(self, count: int, include_threats: bool) -> str:
        """Generate JSON format security logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(count):
            # Generate timestamp
            timestamp = base_time + timedelta(
                minutes=random.randint(0, 7 * 24 * 60)
            )
            
            # Decide if this should be a suspicious event
            is_suspicious = include_threats and random.random() < 0.05  # 5% suspicious
            
            log_entry = {
                "timestamp": timestamp.isoformat(),
                "event_id": str(uuid.uuid4()),
                "source_ip": self._get_ip(is_suspicious),
                "destination_ip": random.choice(self.sample_ips[:6]),  # Internal IPs
                "user": self._get_user(is_suspicious),
                "event_type": self._get_event_type(is_suspicious),
                "system": random.choice(self.sample_systems),
                "result": self._get_result(is_suspicious),
                "severity": self._get_severity(is_suspicious),
                "details": self._generate_event_details(is_suspicious)
            }
            
            logs.append(json.dumps(log_entry))
        
        return '\n'.join(logs)
    
    def _generate_csv_logs(self, count: int, include_threats: bool) -> str:
        """Generate CSV format security logs"""
        headers = [
            "timestamp", "event_id", "source_ip", "destination_ip",
            "user", "event_type", "system", "result", "severity", "details"
        ]
        
        lines = [','.join(headers)]
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(count):
            timestamp = base_time + timedelta(
                minutes=random.randint(0, 7 * 24 * 60)
            )
            
            is_suspicious = include_threats and random.random() < 0.05
            
            row = [
                timestamp.isoformat(),
                str(uuid.uuid4()),
                self._get_ip(is_suspicious),
                random.choice(self.sample_ips[:6]),
                self._get_user(is_suspicious),
                self._get_event_type(is_suspicious),
                random.choice(self.sample_systems),
                self._get_result(is_suspicious),
                self._get_severity(is_suspicious),
                f'"{self._generate_event_details(is_suspicious)}"'
            ]
            
            lines.append(','.join(row))
        
        return '\n'.join(lines)
    
    def _generate_cloudtrail_logs(self, count: int, include_threats: bool) -> str:
        """Generate CloudTrail format logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        aws_events = [
            "AssumeRole", "CreateUser", "DeleteUser", "AttachUserPolicy",
            "CreateBucket", "DeleteBucket", "GetObject", "PutObject",
            "RunInstances", "TerminateInstances", "CreateSecurityGroup"
        ]
        
        for i in range(count):
            timestamp = base_time + timedelta(
                minutes=random.randint(0, 7 * 24 * 60)
            )
            
            is_suspicious = include_threats and random.random() < 0.05
            
            log_entry = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser" if not is_suspicious else "Root",
                    "principalId": f"AIDA{random.randint(100000, 999999)}",
                    "arn": f"arn:aws:iam::123456789012:user/{self._get_user(is_suspicious)}",
                    "accountId": "123456789012",
                    "userName": self._get_user(is_suspicious)
                },
                "eventTime": timestamp.isoformat() + "Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": random.choice(aws_events),
                "awsRegion": "us-east-1",
                "sourceIPAddress": self._get_ip(is_suspicious),
                "userAgent": "aws-cli/2.0.0 Python/3.8.0",
                "requestParameters": {},
                "responseElements": None,
                "requestID": str(uuid.uuid4()),
                "eventID": str(uuid.uuid4()),
                "eventType": "AwsApiCall",
                "apiVersion": "2010-05-08",
                "recipientAccountId": "123456789012"
            }
            
            logs.append(json.dumps(log_entry))
        
        return '\n'.join(logs)
    
    def _generate_syslog_logs(self, count: int, include_threats: bool) -> str:
        """Generate syslog format logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        facilities = ["auth", "daemon", "kern", "mail", "user", "local0"]
        severities = ["info", "warning", "error", "critical"]
        
        for i in range(count):
            timestamp = base_time + timedelta(
                minutes=random.randint(0, 7 * 24 * 60)
            )
            
            is_suspicious = include_threats and random.random() < 0.05
            
            # Syslog format: timestamp hostname facility.severity: message
            hostname = random.choice(self.sample_systems)
            facility = random.choice(facilities)
            severity = "error" if is_suspicious else random.choice(severities)
            
            if is_suspicious:
                message = f"Failed login attempt for user {self._get_user(True)} from {self._get_ip(True)}"
            else:
                message = f"User {self._get_user(False)} logged in successfully from {self._get_ip(False)}"
            
            log_line = f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} {facility}.{severity}: {message}"
            logs.append(log_line)
        
        return '\n'.join(logs)
    
    def _generate_vpc_flow_logs(self, count: int, include_threats: bool) -> str:
        """Generate VPC Flow Logs format"""
        logs = []
        base_time = datetime.now() - timedelta(days=7)
        
        # VPC Flow Logs header
        logs.append("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action")
        
        for i in range(count):
            timestamp = base_time + timedelta(
                minutes=random.randint(0, 7 * 24 * 60)
            )
            
            is_suspicious = include_threats and random.random() < 0.05
            
            window_start = int(timestamp.timestamp())
            window_end = window_start + 60  # 1 minute window
            
            src_ip = self._get_ip(is_suspicious)
            dst_ip = random.choice(self.sample_ips[:6])
            
            # Suspicious traffic patterns
            if is_suspicious:
                src_port = random.choice([22, 23, 3389, 1433, 3306])  # Common attack ports
                dst_port = random.choice([80, 443, 22, 3389])
                packets = random.randint(100, 1000)  # High packet count
                action = "REJECT" if random.random() < 0.7 else "ACCEPT"
            else:
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 53, 25])
                packets = random.randint(1, 50)
                action = "ACCEPT"
            
            bytes_transferred = packets * random.randint(64, 1500)
            
            log_line = f"2 123456789012 eni-{random.randint(10000000, 99999999)} {src_ip} {dst_ip} {src_port} {dst_port} 6 {packets} {bytes_transferred} {window_start} {window_end} {action}"
            logs.append(log_line)
        
        return '\n'.join(logs)
    
    def _get_ip(self, suspicious: bool) -> str:
        """Get IP address, potentially suspicious"""
        if suspicious:
            return random.choice(self.suspicious_patterns["suspicious_ips"])
        else:
            return random.choice(self.sample_ips)
    
    def _get_user(self, suspicious: bool) -> str:
        """Get username, potentially suspicious"""
        if suspicious:
            return random.choice(self.suspicious_patterns["failed_logins"])
        else:
            return random.choice(self.sample_users)
    
    def _get_event_type(self, suspicious: bool) -> str:
        """Get event type, potentially suspicious"""
        if suspicious:
            return random.choice(self.suspicious_patterns["suspicious_events"])
        else:
            return random.choice(self.sample_events)
    
    def _get_result(self, suspicious: bool) -> str:
        """Get event result"""
        if suspicious:
            return random.choice(["FAILED", "DENIED", "ERROR"])
        else:
            return random.choice(["SUCCESS", "ALLOWED", "COMPLETED"])
    
    def _get_severity(self, suspicious: bool) -> str:
        """Get event severity"""
        if suspicious:
            return random.choice(["HIGH", "CRITICAL"])
        else:
            return random.choice(["LOW", "MEDIUM", "INFO"])
    
    def _generate_event_details(self, suspicious: bool) -> str:
        """Generate event details"""
        if suspicious:
            details = [
                "Multiple failed authentication attempts detected",
                "Unusual access pattern from external IP",
                "Administrative action performed outside business hours",
                "Suspicious file access detected",
                "Potential brute force attack in progress"
            ]
        else:
            details = [
                "Normal user authentication",
                "Routine system maintenance",
                "Standard file access",
                "Regular backup operation",
                "Scheduled system update"
            ]
        
        return random.choice(details)
    
    def generate_critical_issues_sample(self) -> List[Dict[str, Any]]:
        """Generate sample critical security issues for immediate demonstration"""
        issues = [
            {
                "issue_id": "CRIT-001",
                "title": "Brute Force Attack Detected",
                "severity": "CRITICAL",
                "description": "Multiple failed login attempts from external IP 203.0.113.50 targeting admin accounts",
                "affected_systems": ["web-server-01", "app-server-01"],
                "first_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
                "last_seen": datetime.now().isoformat(),
                "event_count": 47,
                "recommendation": "Block IP 203.0.113.50 immediately and review admin account security",
                "business_impact": "High - Potential system compromise if successful"
            },
            {
                "issue_id": "HIGH-002", 
                "title": "Unusual Administrative Activity",
                "severity": "HIGH",
                "description": "Administrative actions performed outside business hours by service_account",
                "affected_systems": ["db-server-01"],
                "first_seen": (datetime.now() - timedelta(hours=6)).isoformat(),
                "last_seen": (datetime.now() - timedelta(hours=4)).isoformat(),
                "event_count": 12,
                "recommendation": "Verify legitimacy of after-hours administrative activities",
                "business_impact": "Medium - Potential unauthorized access to sensitive data"
            },
            {
                "issue_id": "MED-003",
                "title": "Suspicious File Access Pattern",
                "severity": "MEDIUM", 
                "description": "Unusual file access patterns detected from workstation-01",
                "affected_systems": ["workstation-01"],
                "first_seen": (datetime.now() - timedelta(hours=8)).isoformat(),
                "last_seen": (datetime.now() - timedelta(hours=1)).isoformat(),
                "event_count": 23,
                "recommendation": "Review file access logs and user activity for workstation-01",
                "business_impact": "Low - Potential data exfiltration risk"
            }
        ]
        
        return issues
    
    def generate_quick_insights(self) -> Dict[str, Any]:
        """Generate sample insights for immediate demonstration"""
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "overall_security_score": 72,  # Out of 100
            "total_events_analyzed": 1000,
            "critical_issues": 1,
            "high_priority_issues": 1,
            "medium_priority_issues": 1,
            "key_findings": [
                "Brute force attack detected from external IP",
                "Unusual administrative activity outside business hours",
                "Multiple systems showing suspicious access patterns"
            ],
            "immediate_actions": [
                "Block suspicious IP address 203.0.113.50",
                "Review administrative account activities",
                "Implement additional monitoring for off-hours activities"
            ],
            "security_trends": {
                "failed_logins_24h": 47,
                "successful_logins_24h": 234,
                "admin_actions_24h": 12,
                "external_connections_24h": 156
            },
            "compliance_status": {
                "access_controls": "94% compliant",
                "audit_logging": "87% compliant", 
                "password_policies": "91% compliant"
            }
        }