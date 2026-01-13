"""
Smart Data Detective - Athena integration for intelligent security data querying.
"""

from aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective
from aws_bedrock_athena_ai.data_detective.query_generator import QueryGenerator
from aws_bedrock_athena_ai.data_detective.data_correlator import DataCorrelator
from aws_bedrock_athena_ai.data_detective.data_source_discovery import DataSourceDiscovery
from aws_bedrock_athena_ai.data_detective.models import (
    DataSource,
    DataSourceType,
    QueryResults,
    CostEstimate,
    CorrelatedData,
    CorrelationPattern,
    DataDiscoveryResult,
    SchemaInfo,
    ColumnInfo
)

__all__ = [
    'SmartDataDetective',
    'QueryGenerator', 
    'DataCorrelator',
    'DataSourceDiscovery',
    'DataSource',
    'DataSourceType',
    'QueryResults',
    'CostEstimate',
    'CorrelatedData',
    'CorrelationPattern',
    'DataDiscoveryResult',
    'SchemaInfo',
    'ColumnInfo'
]