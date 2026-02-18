"""
Automatic data format detection for security logs and data files.

This module analyzes uploaded files to automatically detect their format
and structure, enabling quick onboarding without manual configuration.
"""

import json
import csv
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from io import StringIO, BytesIO

from aws_bedrock_athena_ai.onboarding.models import DataFormat, FormatDetectionResult

logger = logging.getLogger(__name__)


class DataFormatDetector:
    """Automatically detects the format and structure of security data files"""
    
    def __init__(self):
        self.format_patterns = {
            DataFormat.JSON: [
                r'^\s*\{.*\}\s*$',
                r'^\s*\[.*\]\s*$'
            ],
            DataFormat.CSV: [
                r'^[^,\n]*,[^,\n]*,',  # Basic CSV pattern
                r'^"[^"]*","[^"]*",'   # Quoted CSV pattern
            ],
            DataFormat.SYSLOG: [
                r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',  # Standard syslog timestamp
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO timestamp
                r'<\d+>'  # Syslog priority
            ],
            DataFormat.CLOUDTRAIL: [
                r'"eventVersion":\s*"[\d.]+',
                r'"eventTime":\s*"\d{4}-\d{2}-\d{2}T',
                r'"awsRegion":\s*"[^"]+',
                r'"eventName":\s*"[^"]+',
                r'"userIdentity":\s*\{'
            ],
            DataFormat.VPC_FLOW: [
                r'^\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+',  # VPC Flow format
                r'version\s+account-id\s+interface-id'  # VPC Flow header
            ]
        }
        
        # Common security log field patterns
        self.security_field_patterns = {
            'timestamp': [
                'timestamp', 'time', 'eventTime', 'logTime', 'date',
                '@timestamp', 'event_time', 'log_time'
            ],
            'source_ip': [
                'sourceIPAddress', 'src_ip', 'source_ip', 'srcaddr',
                'client_ip', 'remote_addr', 'srcIP'
            ],
            'destination_ip': [
                'destinationIPAddress', 'dst_ip', 'dest_ip', 'dstaddr',
                'server_ip', 'target_ip', 'dstIP'
            ],
            'user': [
                'userName', 'user', 'userid', 'username', 'user_name',
                'principal', 'actor', 'subject'
            ],
            'event_type': [
                'eventName', 'event_type', 'action', 'activity',
                'event', 'operation', 'method'
            ],
            'severity': [
                'severity', 'level', 'priority', 'alert_level',
                'risk_level', 'criticality'
            ]
        }
    
    def detect_format(self, file_content: str, filename: str = "") -> FormatDetectionResult:
        """
        Detect the format of uploaded security data.
        
        Args:
            file_content: Content of the uploaded file
            filename: Original filename for additional context
            
        Returns:
            FormatDetectionResult with detected format and confidence
        """
        logger.info(f"🔍 Detecting format for file: {filename}")
        
        # Try to detect format based on content patterns
        format_scores = {}
        
        # Sample first few lines for analysis
        lines = file_content.strip().split('\n')[:10]
        sample_content = '\n'.join(lines)
        
        # Test each format pattern
        for data_format, patterns in self.format_patterns.items():
            score = 0.0
            for pattern in patterns:
                matches = len(re.findall(pattern, sample_content, re.MULTILINE | re.IGNORECASE))
                if matches > 0:
                    score += matches / len(lines)
            
            format_scores[data_format] = score
        
        # Additional filename-based hints
        filename_lower = filename.lower()
        if '.json' in filename_lower or 'cloudtrail' in filename_lower:
            format_scores[DataFormat.JSON] = format_scores.get(DataFormat.JSON, 0) + 0.3
            format_scores[DataFormat.CLOUDTRAIL] = format_scores.get(DataFormat.CLOUDTRAIL, 0) + 0.5
        elif '.csv' in filename_lower:
            format_scores[DataFormat.CSV] = format_scores.get(DataFormat.CSV, 0) + 0.5
        elif '.log' in filename_lower or 'syslog' in filename_lower:
            format_scores[DataFormat.SYSLOG] = format_scores.get(DataFormat.SYSLOG, 0) + 0.3
        elif 'vpc' in filename_lower or 'flow' in filename_lower:
            format_scores[DataFormat.VPC_FLOW] = format_scores.get(DataFormat.VPC_FLOW, 0) + 0.5
        
        # Find the best match
        if not format_scores or max(format_scores.values()) == 0:
            detected_format = DataFormat.UNKNOWN
            confidence = 0.0
        else:
            detected_format = max(format_scores, key=format_scores.get)
            confidence = min(format_scores[detected_format], 1.0)
        
        # Generate schema preview and sample data
        schema_preview, sample_data = self._analyze_structure(file_content, detected_format)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(detected_format, confidence, schema_preview)
        
        # Generate warnings if needed
        warnings = self._generate_warnings(detected_format, confidence, sample_data)
        
        result = FormatDetectionResult(
            detected_format=detected_format,
            confidence_score=confidence,
            schema_preview=schema_preview,
            sample_data=sample_data,
            recommendations=recommendations,
            warnings=warnings
        )
        
        logger.info(f"✅ Format detection complete: {detected_format.value} (confidence: {confidence:.2f})")
        return result
    
    def _analyze_structure(self, content: str, detected_format: DataFormat) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze the structure of the detected format"""
        schema_preview = {}
        sample_data = []
        
        try:
            if detected_format == DataFormat.JSON:
                schema_preview, sample_data = self._analyze_json_structure(content)
            elif detected_format == DataFormat.CSV:
                schema_preview, sample_data = self._analyze_csv_structure(content)
            elif detected_format == DataFormat.CLOUDTRAIL:
                schema_preview, sample_data = self._analyze_cloudtrail_structure(content)
            elif detected_format in [DataFormat.SYSLOG, DataFormat.LOG_TEXT]:
                schema_preview, sample_data = self._analyze_log_structure(content)
            elif detected_format == DataFormat.VPC_FLOW:
                schema_preview, sample_data = self._analyze_vpc_flow_structure(content)
            else:
                schema_preview = {"format": "unknown", "fields": []}
                sample_data = []
                
        except Exception as e:
            logger.warning(f"⚠️ Error analyzing structure: {str(e)}")
            schema_preview = {"format": detected_format.value, "error": str(e)}
            sample_data = []
        
        return schema_preview, sample_data
    
    def _analyze_json_structure(self, content: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze JSON structure"""
        lines = content.strip().split('\n')
        sample_data = []
        fields = set()
        
        # Try to parse first few JSON objects
        for line in lines[:5]:
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        sample_data.append(obj)
                        fields.update(obj.keys())
                except json.JSONDecodeError:
                    continue
        
        # Identify security-relevant fields
        security_fields = self._identify_security_fields(list(fields))
        
        schema_preview = {
            "format": "json",
            "total_fields": len(fields),
            "fields": list(fields)[:20],  # Limit to first 20 fields
            "security_fields": security_fields,
            "sample_count": len(sample_data)
        }
        
        return schema_preview, sample_data
    
    def _analyze_csv_structure(self, content: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze CSV structure"""
        lines = content.strip().split('\n')
        if not lines:
            return {}, []
        
        # Try to detect delimiter
        delimiter = ','
        if '\t' in lines[0]:
            delimiter = '\t'
        elif ';' in lines[0]:
            delimiter = ';'
        
        try:
            # Parse CSV
            csv_reader = csv.DictReader(StringIO(content), delimiter=delimiter)
            sample_data = []
            
            for i, row in enumerate(csv_reader):
                if i >= 5:  # Limit to first 5 rows
                    break
                sample_data.append(dict(row))
            
            fields = list(csv_reader.fieldnames) if csv_reader.fieldnames else []
            security_fields = self._identify_security_fields(fields)
            
            schema_preview = {
                "format": "csv",
                "delimiter": delimiter,
                "total_fields": len(fields),
                "fields": fields,
                "security_fields": security_fields,
                "sample_count": len(sample_data)
            }
            
            return schema_preview, sample_data
            
        except Exception as e:
            logger.warning(f"⚠️ Error parsing CSV: {str(e)}")
            return {"format": "csv", "error": str(e)}, []
    
    def _analyze_cloudtrail_structure(self, content: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze CloudTrail log structure"""
        lines = content.strip().split('\n')
        sample_data = []
        
        for line in lines[:3]:  # CloudTrail logs can be large
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and 'eventName' in obj:
                        sample_data.append(obj)
                except json.JSONDecodeError:
                    continue
        
        # CloudTrail has standard fields
        standard_fields = [
            'eventVersion', 'userIdentity', 'eventTime', 'eventSource',
            'eventName', 'awsRegion', 'sourceIPAddress', 'userAgent',
            'requestParameters', 'responseElements', 'requestID'
        ]
        
        schema_preview = {
            "format": "cloudtrail",
            "standard_fields": standard_fields,
            "security_fields": {
                "timestamp": ["eventTime"],
                "source_ip": ["sourceIPAddress"],
                "user": ["userIdentity"],
                "event_type": ["eventName"],
                "severity": []
            },
            "sample_count": len(sample_data)
        }
        
        return schema_preview, sample_data
    
    def _analyze_log_structure(self, content: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze generic log file structure"""
        lines = content.strip().split('\n')
        sample_data = []
        
        # Try to parse common log formats
        for line in lines[:5]:
            line = line.strip()
            if line:
                # Try to extract timestamp, IP, and other common fields
                parsed = self._parse_log_line(line)
                if parsed:
                    sample_data.append(parsed)
        
        schema_preview = {
            "format": "log_text",
            "line_count": len(lines),
            "sample_count": len(sample_data),
            "common_patterns": self._identify_log_patterns(lines[:10])
        }
        
        return schema_preview, sample_data
    
    def _analyze_vpc_flow_structure(self, content: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze VPC Flow Logs structure"""
        lines = content.strip().split('\n')
        sample_data = []
        
        # VPC Flow Logs have a standard format
        vpc_fields = [
            'version', 'account-id', 'interface-id', 'srcaddr', 'dstaddr',
            'srcport', 'dstport', 'protocol', 'packets', 'bytes',
            'windowstart', 'windowend', 'action'
        ]
        
        for line in lines[:5]:
            parts = line.strip().split()
            if len(parts) >= len(vpc_fields):
                record = dict(zip(vpc_fields, parts))
                sample_data.append(record)
        
        schema_preview = {
            "format": "vpc_flow",
            "fields": vpc_fields,
            "security_fields": {
                "timestamp": ["windowstart", "windowend"],
                "source_ip": ["srcaddr"],
                "destination_ip": ["dstaddr"],
                "event_type": ["action"],
                "severity": []
            },
            "sample_count": len(sample_data)
        }
        
        return schema_preview, sample_data
    
    def _identify_security_fields(self, fields: List[str]) -> Dict[str, List[str]]:
        """Identify which fields contain security-relevant information"""
        security_fields = {}
        
        for category, patterns in self.security_field_patterns.items():
            matches = []
            for field in fields:
                field_lower = field.lower()
                for pattern in patterns:
                    if pattern.lower() in field_lower:
                        matches.append(field)
                        break
            security_fields[category] = matches
        
        return security_fields
    
    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Try to parse a generic log line"""
        # Common log patterns
        patterns = [
            # Apache/Nginx access log
            r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+)',
            # Syslog format
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\S+) (.*)',
            # ISO timestamp format
            r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*Z?) (.*)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                return {
                    "timestamp": groups[0] if groups else None,
                    "raw_line": line,
                    "parsed_fields": len(groups)
                }
        
        return None
    
    def _identify_log_patterns(self, lines: List[str]) -> List[str]:
        """Identify common patterns in log lines"""
        patterns = []
        
        # Check for timestamps
        timestamp_count = sum(1 for line in lines if re.search(r'\d{4}-\d{2}-\d{2}', line))
        if timestamp_count > len(lines) * 0.5:
            patterns.append("Contains timestamps")
        
        # Check for IP addresses
        ip_count = sum(1 for line in lines if re.search(r'\d+\.\d+\.\d+\.\d+', line))
        if ip_count > len(lines) * 0.3:
            patterns.append("Contains IP addresses")
        
        # Check for HTTP status codes
        http_count = sum(1 for line in lines if re.search(r'\s[1-5]\d{2}\s', line))
        if http_count > len(lines) * 0.3:
            patterns.append("Contains HTTP status codes")
        
        return patterns
    
    def _generate_recommendations(self, detected_format: DataFormat, confidence: float, schema_preview: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on detected format"""
        recommendations = []
        
        if confidence < 0.5:
            recommendations.append("Low confidence in format detection. Consider manual format specification.")
        
        if detected_format == DataFormat.JSON:
            recommendations.append("JSON format detected. Consider using Parquet for better query performance.")
        elif detected_format == DataFormat.CSV:
            recommendations.append("CSV format detected. Ensure proper column headers for optimal analysis.")
        elif detected_format == DataFormat.CLOUDTRAIL:
            recommendations.append("CloudTrail logs detected. These are excellent for security analysis!")
        elif detected_format == DataFormat.SYSLOG:
            recommendations.append("Syslog format detected. Consider structured logging for better analysis.")
        elif detected_format == DataFormat.UNKNOWN:
            recommendations.append("Unknown format. Please verify file content and try again.")
        
        # Check for security fields
        security_fields = schema_preview.get('security_fields', {})
        if not any(security_fields.values()):
            recommendations.append("No obvious security fields detected. Verify this is security-related data.")
        
        return recommendations
    
    def _generate_warnings(self, detected_format: DataFormat, confidence: float, sample_data: List[Dict[str, Any]]) -> List[str]:
        """Generate warnings about potential issues"""
        warnings = []
        
        if confidence < 0.3:
            warnings.append("Very low confidence in format detection. Results may be inaccurate.")
        
        if not sample_data:
            warnings.append("No sample data could be parsed. File may be corrupted or in unsupported format.")
        
        if detected_format == DataFormat.UNKNOWN:
            warnings.append("Format could not be determined automatically. Manual configuration required.")
        
        return warnings