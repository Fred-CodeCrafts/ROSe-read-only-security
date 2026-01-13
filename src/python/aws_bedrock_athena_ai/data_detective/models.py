"""
Data models for the Smart Data Detective component.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum


class DataSourceType(Enum):
    """Types of security data sources that can be discovered."""
    SECURITY_LOGS = "security_logs"
    ACCESS_LOGS = "access_logs"
    FIREWALL_LOGS = "firewall_logs"
    VPC_FLOW_LOGS = "vpc_flow_logs"
    CLOUDTRAIL_LOGS = "cloudtrail_logs"
    SYSTEM_CONFIGS = "system_configs"
    VULNERABILITY_SCANS = "vulnerability_scans"
    THREAT_INTELLIGENCE = "threat_intelligence"
    NETWORK_TRAFFIC = "network_traffic"
    APPLICATION_LOGS = "application_logs"
    COMPLIANCE_REPORTS = "compliance_reports"
    UNKNOWN = "unknown"


@dataclass
class ColumnInfo:
    """Information about a database column."""
    name: str
    data_type: str
    nullable: bool = True
    description: Optional[str] = None


@dataclass
class SchemaInfo:
    """Information about the schema of a data source."""
    table_name: str
    columns: List[ColumnInfo] = field(default_factory=list)
    partition_keys: List[str] = field(default_factory=list)
    sample_data: List[Dict[str, Any]] = field(default_factory=list)
    row_count_estimate: Optional[int] = None
    last_updated: Optional[datetime] = None
    
    def has_column(self, column_name: str) -> bool:
        """Check if schema has a specific column."""
        return column_name.lower() in [col.name.lower() for col in self.columns]
    
    def get_time_columns(self) -> List[str]:
        """Get columns that likely contain timestamp data."""
        time_indicators = ['timestamp', 'time', 'date', 'created', 'modified', 'logged']
        return [
            col.name for col in self.columns
            if any(indicator in col.name.lower() for indicator in time_indicators)
        ]
    
    def get_column_names(self) -> List[str]:
        """Get list of all column names."""
        return [col.name for col in self.columns]


@dataclass
class DataSource:
    """Represents a discovered security data source."""
    source_id: str
    source_type: DataSourceType
    s3_location: str
    schema_info: SchemaInfo
    confidence_score: float  # How confident we are this is the detected type
    data_format: str = "parquet"  # parquet, json, csv, etc.
    compression: Optional[str] = None  # gzip, snappy, etc.
    discovery_timestamp: datetime = field(default_factory=datetime.now)
    
    # Metadata for optimization
    estimated_size_gb: float = 0.0
    avg_query_cost_usd: float = 0.0
    query_frequency: int = 0  # How often this source is queried
    
    def is_time_partitioned(self) -> bool:
        """Check if this data source is partitioned by time."""
        return any(
            'year' in key.lower() or 'month' in key.lower() or 'day' in key.lower()
            for key in self.schema_info.partition_keys
        )


@dataclass
class QueryResults:
    """Results from executing an Athena query."""
    query_id: str
    data: List[Dict[str, Any]]
    column_names: List[str]
    row_count: int
    data_scanned_gb: float
    execution_time_ms: int
    cost_usd: float
    query_sql: str
    
    # Metadata
    execution_timestamp: datetime = field(default_factory=datetime.now)
    source_tables: List[str] = field(default_factory=list)
    
    def get_column_values(self, column_name: str) -> List[Any]:
        """Get all values for a specific column."""
        return [row.get(column_name) for row in self.data if column_name in row]
    
    def filter_rows(self, condition_func) -> List[Dict[str, Any]]:
        """Filter rows based on a condition function."""
        return [row for row in self.data if condition_func(row)]


@dataclass
class CostEstimate:
    """Estimate of query execution cost."""
    estimated_data_scanned_gb: float
    estimated_cost_usd: float
    confidence: float  # 0.0 to 1.0
    factors: List[str] = field(default_factory=list)  # Factors affecting the estimate
    
    def is_within_free_tier(self, monthly_usage_gb: float = 0.0) -> bool:
        """Check if this query would stay within AWS Free Tier limits."""
        # Athena Free Tier: 10 TB (10,000 GB) per month
        free_tier_limit_gb = 10000.0
        return (monthly_usage_gb + self.estimated_data_scanned_gb) <= free_tier_limit_gb


@dataclass
class CorrelationPattern:
    """A pattern found when correlating data across sources."""
    pattern_id: str
    pattern_type: str  # temporal, spatial, behavioral, etc.
    description: str
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    affected_sources: List[str] = field(default_factory=list)
    time_range: Optional[tuple] = None  # (start_time, end_time)


@dataclass
class CorrelatedData:
    """Results from correlating data across multiple sources."""
    primary_results: QueryResults
    related_data: Dict[str, QueryResults] = field(default_factory=dict)
    correlation_patterns: List[CorrelationPattern] = field(default_factory=list)
    correlation_score: float = 0.0  # Overall correlation strength
    
    def get_timeline_events(self) -> List[Dict[str, Any]]:
        """Get all events sorted by timestamp for timeline analysis."""
        all_events = []
        
        # Add primary results
        for row in self.primary_results.data:
            if 'timestamp' in row:
                all_events.append({
                    'timestamp': row['timestamp'],
                    'source': 'primary',
                    'data': row
                })
        
        # Add related data
        for source_name, results in self.related_data.items():
            for row in results.data:
                if 'timestamp' in row:
                    all_events.append({
                        'timestamp': row['timestamp'],
                        'source': source_name,
                        'data': row
                    })
        
        # Sort by timestamp
        return sorted(all_events, key=lambda x: x['timestamp'])


@dataclass
class DataDiscoveryResult:
    """Result of data source discovery process."""
    discovered_sources: List[DataSource]
    total_sources_found: int
    discovery_duration_ms: int
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def get_sources_by_type(self, source_type: DataSourceType) -> List[DataSource]:
        """Get all discovered sources of a specific type."""
        return [source for source in self.discovered_sources if source.source_type == source_type]
    
    def get_high_confidence_sources(self, min_confidence: float = 0.8) -> List[DataSource]:
        """Get sources with high confidence scores."""
        return [source for source in self.discovered_sources if source.confidence_score >= min_confidence]