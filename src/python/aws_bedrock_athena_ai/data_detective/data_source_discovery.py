"""
Data Source Discovery component for automatically finding and cataloging security data.
"""

import boto3
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from dataclasses import dataclass

from aws_bedrock_athena_ai.data_detective.models import (
    DataSource, 
    DataSourceType, 
    SchemaInfo, 
    DataDiscoveryResult
)


logger = logging.getLogger(__name__)


class DataSourceDiscovery:
    """
    Automatically discovers and catalogs security-related data sources in S3.
    
    This component scans S3 buckets for security data, analyzes file structures,
    and creates a catalog of available data sources for querying.
    """
    
    def __init__(self, aws_region: str = 'us-east-1'):
        """Initialize the data source discovery component."""
        self.aws_region = aws_region
        self.s3_client = boto3.client('s3', region_name=aws_region)
        self.athena_client = boto3.client('athena', region_name=aws_region)
        self.glue_client = boto3.client('glue', region_name=aws_region)
        
        # Patterns for identifying security data types
        self.security_patterns = {
            DataSourceType.SECURITY_LOGS: [
                r'security[_-]?log',
                r'auth[_-]?log',
                r'syslog',
                r'event[_-]?log'
            ],
            DataSourceType.ACCESS_LOGS: [
                r'access[_-]?log',
                r'nginx[_-]?log',
                r'apache[_-]?log',
                r'web[_-]?log'
            ],
            DataSourceType.FIREWALL_LOGS: [
                r'firewall[_-]?log',
                r'fw[_-]?log',
                r'iptables',
                r'pf[_-]?log'
            ],
            DataSourceType.VPC_FLOW_LOGS: [
                r'vpc[_-]?flow',
                r'flow[_-]?log',
                r'network[_-]?flow'
            ],
            DataSourceType.CLOUDTRAIL_LOGS: [
                r'cloudtrail',
                r'aws[_-]?trail',
                r'api[_-]?log'
            ],
            DataSourceType.SYSTEM_CONFIGS: [
                r'config',
                r'configuration',
                r'settings',
                r'inventory'
            ],
            DataSourceType.VULNERABILITY_SCANS: [
                r'vuln',
                r'vulnerability',
                r'scan[_-]?result',
                r'nessus',
                r'openvas'
            ],
            DataSourceType.THREAT_INTELLIGENCE: [
                r'threat[_-]?intel',
                r'ioc',
                r'indicator',
                r'malware'
            ]
        }
    
    def discover_security_data_sources(self, 
                                     bucket_names: Optional[List[str]] = None,
                                     prefix_filter: Optional[str] = None) -> DataDiscoveryResult:
        """
        Discover security data sources across S3 buckets.
        
        Args:
            bucket_names: Specific buckets to scan. If None, scans accessible buckets.
            prefix_filter: Only scan objects with this prefix.
            
        Returns:
            DataDiscoveryResult with discovered sources and metadata.
        """
        start_time = datetime.now()
        discovered_sources = []
        errors = []
        warnings = []
        
        try:
            # Get list of buckets to scan
            if bucket_names is None:
                bucket_names = self._get_accessible_buckets()
            
            logger.info(f"Scanning {len(bucket_names)} buckets for security data")
            
            for bucket_name in bucket_names:
                try:
                    bucket_sources = self._scan_bucket_for_security_data(
                        bucket_name, prefix_filter
                    )
                    discovered_sources.extend(bucket_sources)
                    logger.info(f"Found {len(bucket_sources)} sources in bucket {bucket_name}")
                    
                except Exception as e:
                    error_msg = f"Error scanning bucket {bucket_name}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            # Enhance discovered sources with schema information
            for source in discovered_sources:
                try:
                    self._enhance_source_with_schema(source)
                except Exception as e:
                    warning_msg = f"Could not enhance schema for {source.source_id}: {str(e)}"
                    warnings.append(warning_msg)
                    logger.warning(warning_msg)
            
        except Exception as e:
            error_msg = f"Critical error during discovery: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
        
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return DataDiscoveryResult(
            discovered_sources=discovered_sources,
            total_sources_found=len(discovered_sources),
            discovery_duration_ms=duration_ms,
            errors=errors,
            warnings=warnings
        )
    
    def _get_accessible_buckets(self) -> List[str]:
        """Get list of S3 buckets accessible to the current credentials."""
        try:
            response = self.s3_client.list_buckets()
            return [bucket['Name'] for bucket in response['Buckets']]
        except Exception as e:
            logger.error(f"Could not list buckets: {str(e)}")
            return []
    
    def _scan_bucket_for_security_data(self, 
                                     bucket_name: str, 
                                     prefix_filter: Optional[str] = None) -> List[DataSource]:
        """Scan a single bucket for security-related data."""
        sources = []
        
        try:
            # List objects in bucket
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                Prefix=prefix_filter or ''
            )
            
            # Group objects by potential data source
            data_source_groups = {}
            
            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                    
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Skip very small files (likely not data files)
                    if obj['Size'] < 1024:  # Less than 1KB
                        continue
                    
                    # Identify potential data source type and group
                    source_type, confidence = self._identify_data_source_type(key)
                    if source_type != DataSourceType.UNKNOWN:
                        # Group by common prefix (likely same dataset)
                        group_key = self._get_data_source_group_key(key)
                        
                        if group_key not in data_source_groups:
                            data_source_groups[group_key] = {
                                'type': source_type,
                                'confidence': confidence,
                                'objects': [],
                                'total_size': 0
                            }
                        
                        data_source_groups[group_key]['objects'].append(obj)
                        data_source_groups[group_key]['total_size'] += obj['Size']
            
            # Create DataSource objects from groups
            for group_key, group_info in data_source_groups.items():
                if len(group_info['objects']) > 0:  # Only create if we have objects
                    source = self._create_data_source_from_group(
                        bucket_name, group_key, group_info
                    )
                    sources.append(source)
        
        except Exception as e:
            logger.error(f"Error scanning bucket {bucket_name}: {str(e)}")
        
        return sources
    
    def _identify_data_source_type(self, s3_key: str) -> tuple[DataSourceType, float]:
        """
        Identify the type of security data based on S3 key patterns.
        
        Returns:
            Tuple of (DataSourceType, confidence_score)
        """
        key_lower = s3_key.lower()
        
        for source_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                if re.search(pattern, key_lower):
                    # Higher confidence for more specific patterns
                    confidence = 0.9 if len(pattern) > 10 else 0.7
                    return source_type, confidence
        
        # Check for common security file extensions
        if any(ext in key_lower for ext in ['.log', '.json', '.csv', '.parquet']):
            # Check if path contains security-related directories
            security_dirs = ['security', 'logs', 'audit', 'events', 'monitoring']
            if any(dir_name in key_lower for dir_name in security_dirs):
                return DataSourceType.SECURITY_LOGS, 0.5
        
        return DataSourceType.UNKNOWN, 0.0
    
    def _get_data_source_group_key(self, s3_key: str) -> str:
        """
        Generate a group key for similar data files.
        
        This groups files that are likely part of the same dataset
        (e.g., partitioned by date).
        """
        # Remove file extension and date-like patterns
        key = s3_key.lower()
        
        # Remove common date patterns
        key = re.sub(r'/\d{4}/\d{2}/\d{2}/', '/{date}/', key)
        key = re.sub(r'/year=\d{4}/', '/year={year}/', key)
        key = re.sub(r'/month=\d{2}/', '/month={month}/', key)
        key = re.sub(r'/day=\d{2}/', '/day={day}/', key)
        key = re.sub(r'_\d{4}-\d{2}-\d{2}', '_{date}', key)
        key = re.sub(r'_\d{8}', '_{date}', key)
        
        # Remove file extension
        key = re.sub(r'\.[^/]+$', '', key)
        
        return key
    
    def _create_data_source_from_group(self, 
                                     bucket_name: str, 
                                     group_key: str, 
                                     group_info: Dict[str, Any]) -> DataSource:
        """Create a DataSource object from a group of related files."""
        
        # Generate unique source ID
        source_id = f"{bucket_name}_{hash(group_key) % 10000:04d}"
        
        # Estimate size in GB
        size_gb = group_info['total_size'] / (1024 ** 3)
        
        # Create basic schema info (will be enhanced later)
        schema_info = SchemaInfo(
            table_name=f"security_data_{source_id}",
            columns={},  # Will be populated by schema enhancement
            row_count_estimate=None
        )
        
        # S3 location (use the common prefix)
        s3_location = f"s3://{bucket_name}/{group_key.replace('{date}', '*').replace('{year}', '*').replace('{month}', '*').replace('{day}', '*')}"
        
        return DataSource(
            source_id=source_id,
            source_type=group_info['type'],
            s3_location=s3_location,
            schema_info=schema_info,
            confidence_score=group_info['confidence'],
            estimated_size_gb=size_gb,
            discovery_timestamp=datetime.now()
        )
    
    def _enhance_source_with_schema(self, source: DataSource) -> None:
        """
        Enhance a data source with detailed schema information.
        
        This method attempts to infer schema by sampling data files.
        """
        try:
            # Try to get schema from Glue Data Catalog first
            glue_schema = self._get_glue_schema(source)
            if glue_schema:
                source.schema_info = glue_schema
                return
            
            # If no Glue schema, try to infer from sample data
            sample_schema = self._infer_schema_from_sample(source)
            if sample_schema:
                source.schema_info = sample_schema
                
        except Exception as e:
            logger.warning(f"Could not enhance schema for {source.source_id}: {str(e)}")
    
    def _get_glue_schema(self, source: DataSource) -> Optional[SchemaInfo]:
        """Try to get schema information from AWS Glue Data Catalog."""
        try:
            # This is a simplified implementation
            # In practice, you'd need to map S3 locations to Glue tables
            return None
        except Exception:
            return None
    
    def _infer_schema_from_sample(self, source: DataSource) -> Optional[SchemaInfo]:
        """
        Infer schema by sampling data from the source.
        
        This is a basic implementation that handles common formats.
        """
        try:
            # Parse S3 location to get bucket and prefix
            s3_parts = source.s3_location.replace('s3://', '').split('/', 1)
            bucket_name = s3_parts[0]
            prefix = s3_parts[1] if len(s3_parts) > 1 else ''
            
            # Find a sample file
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=prefix.replace('*', ''),
                MaxKeys=1
            )
            
            if 'Contents' not in response or len(response['Contents']) == 0:
                return None
            
            sample_key = response['Contents'][0]['Key']
            
            # Download and analyze sample
            obj_response = self.s3_client.get_object(Bucket=bucket_name, Key=sample_key)
            sample_data = obj_response['Body'].read()
            
            # Try to parse based on file extension
            if sample_key.endswith('.json'):
                return self._parse_json_schema(sample_data, source.schema_info.table_name)
            elif sample_key.endswith('.csv'):
                return self._parse_csv_schema(sample_data, source.schema_info.table_name)
            # Add more format handlers as needed
            
        except Exception as e:
            logger.warning(f"Could not infer schema from sample: {str(e)}")
        
        return None
    
    def _parse_json_schema(self, sample_data: bytes, table_name: str) -> SchemaInfo:
        """Parse schema from JSON sample data."""
        try:
            # Take first few lines for JSON Lines format
            lines = sample_data.decode('utf-8').strip().split('\n')[:5]
            
            columns = {}
            sample_records = []
            
            for line in lines:
                if line.strip():
                    record = json.loads(line)
                    sample_records.append(record)
                    
                    # Infer column types
                    for key, value in record.items():
                        if key not in columns:
                            if isinstance(value, str):
                                columns[key] = 'string'
                            elif isinstance(value, int):
                                columns[key] = 'bigint'
                            elif isinstance(value, float):
                                columns[key] = 'double'
                            elif isinstance(value, bool):
                                columns[key] = 'boolean'
                            else:
                                columns[key] = 'string'
            
            return SchemaInfo(
                table_name=table_name,
                columns=columns,
                sample_data=sample_records[:3]  # Keep only first 3 samples
            )
            
        except Exception as e:
            logger.error(f"Error parsing JSON schema: {str(e)}")
            return SchemaInfo(table_name=table_name, columns={})
    
    def _parse_csv_schema(self, sample_data: bytes, table_name: str) -> SchemaInfo:
        """Parse schema from CSV sample data."""
        try:
            lines = sample_data.decode('utf-8').strip().split('\n')
            
            if len(lines) < 2:
                return SchemaInfo(table_name=table_name, columns={})
            
            # Assume first line is header
            headers = [col.strip() for col in lines[0].split(',')]
            
            # Infer types from second line
            columns = {}
            if len(lines) > 1:
                values = [val.strip() for val in lines[1].split(',')]
                for i, header in enumerate(headers):
                    if i < len(values):
                        # Simple type inference
                        val = values[i]
                        try:
                            int(val)
                            columns[header] = 'bigint'
                        except ValueError:
                            try:
                                float(val)
                                columns[header] = 'double'
                            except ValueError:
                                columns[header] = 'string'
                    else:
                        columns[header] = 'string'
            
            # Create sample data
            sample_records = []
            for line in lines[1:4]:  # Take up to 3 sample rows
                if line.strip():
                    values = [val.strip() for val in line.split(',')]
                    record = {}
                    for i, header in enumerate(headers):
                        if i < len(values):
                            record[header] = values[i]
                    sample_records.append(record)
            
            return SchemaInfo(
                table_name=table_name,
                columns=columns,
                sample_data=sample_records
            )
            
        except Exception as e:
            logger.error(f"Error parsing CSV schema: {str(e)}")
            return SchemaInfo(table_name=table_name, columns={})