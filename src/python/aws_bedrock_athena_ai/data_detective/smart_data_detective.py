"""
Smart Data Detective - Main component that integrates query generation and data correlation.
"""

import boto3
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext
from aws_bedrock_athena_ai.data_detective.models import DataSource, QueryResults, CorrelatedData, CostEstimate
from aws_bedrock_athena_ai.data_detective.data_source_discovery import DataSourceDiscovery
from aws_bedrock_athena_ai.data_detective.query_generator import QueryGenerator
from aws_bedrock_athena_ai.data_detective.data_correlator import DataCorrelator


logger = logging.getLogger(__name__)


class SmartDataDetective:
    """
    Main Smart Data Detective component that orchestrates data discovery, 
    query generation, and correlation analysis.
    
    This is the primary interface for converting security intents into 
    actionable data insights through optimized querying and correlation.
    """
    
    def __init__(self, aws_region: str = 'us-east-1'):
        """Initialize the Smart Data Detective."""
        self.aws_region = aws_region
        self.athena_client = boto3.client('athena', region_name=aws_region)
        
        # Initialize components
        self.data_discovery = DataSourceDiscovery(aws_region)
        self.query_generator = QueryGenerator()
        self.data_correlator = DataCorrelator(self.athena_client)
        
        # Cache for discovered data sources
        self._data_source_cache = {}
        self._cache_timestamp = None
        self._cache_ttl_minutes = 30
    
    def discover_security_data_sources(self, 
                                     bucket_names: Optional[List[str]] = None,
                                     force_refresh: bool = False) -> List[DataSource]:
        """
        Discover available security data sources.
        
        Args:
            bucket_names: Specific buckets to scan
            force_refresh: Force refresh of cached data sources
            
        Returns:
            List of discovered data sources
        """
        try:
            # Check cache first
            if not force_refresh and self._is_cache_valid():
                cache_key = str(bucket_names) if bucket_names else 'all'
                if cache_key in self._data_source_cache:
                    logger.info("Returning cached data sources")
                    return self._data_source_cache[cache_key]
            
            # Discover data sources
            logger.info("Discovering security data sources...")
            discovery_result = self.data_discovery.discover_security_data_sources(bucket_names)
            
            # Update cache
            cache_key = str(bucket_names) if bucket_names else 'all'
            self._data_source_cache[cache_key] = discovery_result.discovered_sources
            self._cache_timestamp = datetime.now()
            
            logger.info(f"Discovered {len(discovery_result.discovered_sources)} data sources")
            
            if discovery_result.errors:
                logger.warning(f"Discovery completed with {len(discovery_result.errors)} errors")
            
            return discovery_result.discovered_sources
            
        except Exception as e:
            logger.error(f"Error discovering data sources: {str(e)}")
            return []
    
    def generate_optimized_query(self, 
                               intent: SecurityIntent, 
                               context: QueryContext,
                               available_sources: Optional[List[DataSource]] = None) -> str:
        """
        Generate an optimized Athena SQL query for the given security intent.
        
        Args:
            intent: Security intent to query for
            context: Query context with constraints
            available_sources: Available data sources (auto-discovered if None)
            
        Returns:
            Optimized SQL query string
        """
        try:
            # Get available data sources if not provided
            if available_sources is None:
                available_sources = self.discover_security_data_sources()
            
            if not available_sources:
                raise ValueError("No data sources available for query generation")
            
            # Generate optimized query
            query = self.query_generator.generate_optimized_query(
                intent, context, available_sources
            )
            
            logger.info("Generated optimized query successfully")
            return query
            
        except Exception as e:
            logger.error(f"Error generating optimized query: {str(e)}")
            raise
    
    def estimate_query_cost(self, 
                          query: str, 
                          data_sources: Optional[List[DataSource]] = None) -> CostEstimate:
        """
        Estimate the cost of executing a query.
        
        Args:
            query: SQL query to estimate
            data_sources: Data sources involved (auto-discovered if None)
            
        Returns:
            Cost estimate with confidence level
        """
        try:
            # Get data sources if not provided
            if data_sources is None:
                data_sources = self.discover_security_data_sources()
            
            # Generate cost estimate
            cost_estimate = self.query_generator.estimate_query_cost(query, data_sources)
            
            logger.info(f"Estimated query cost: ${cost_estimate.estimated_cost_usd:.4f}")
            return cost_estimate
            
        except Exception as e:
            logger.error(f"Error estimating query cost: {str(e)}")
            return CostEstimate(
                estimated_data_scanned_gb=0.0,
                estimated_cost_usd=0.0,
                confidence=0.0,
                factors=[f"estimation_error: {str(e)}"]
            )
    
    def execute_correlation_analysis(self, 
                                   primary_results: QueryResults,
                                   context: QueryContext,
                                   related_sources: Optional[List[DataSource]] = None) -> CorrelatedData:
        """
        Execute cross-source correlation analysis.
        
        Args:
            primary_results: Primary query results to correlate
            context: Query context for correlation parameters
            related_sources: Related sources to correlate with (auto-discovered if None)
            
        Returns:
            Correlated data with patterns and insights
        """
        try:
            # Get related sources if not provided
            if related_sources is None:
                all_sources = self.discover_security_data_sources()
                # Filter out sources that were likely used in primary query
                related_sources = [
                    source for source in all_sources
                    if source.schema_info.table_name not in primary_results.source_tables
                ]
            
            # Execute correlation analysis
            correlated_data = self.data_correlator.correlate_data_across_sources(
                primary_results, related_sources, context
            )
            
            logger.info(f"Correlation analysis found {len(correlated_data.correlation_patterns)} patterns")
            return correlated_data
            
        except Exception as e:
            logger.error(f"Error executing correlation analysis: {str(e)}")
            return CorrelatedData(
                primary_results=primary_results,
                related_data={},
                correlation_patterns=[],
                correlation_score=0.0
            )
    
    def analyze_time_series_trends(self, 
                                 correlated_data: CorrelatedData,
                                 time_window: str = 'medium_term') -> List[Dict[str, Any]]:
        """
        Analyze time-series trends in correlated data.
        
        Args:
            correlated_data: Correlated data to analyze
            time_window: Time window for trend analysis
            
        Returns:
            List of trend analysis results
        """
        try:
            trends = self.data_correlator.analyze_time_series_trends(
                correlated_data, time_window
            )
            
            logger.info(f"Time-series analysis identified {len(trends)} trends")
            return trends
            
        except Exception as e:
            logger.error(f"Error analyzing time-series trends: {str(e)}")
            return []
    
    def execute_comprehensive_analysis(self, 
                                     intent: SecurityIntent, 
                                     context: QueryContext,
                                     include_correlation: bool = True,
                                     include_trends: bool = True) -> Dict[str, Any]:
        """
        Execute comprehensive security data analysis.
        
        This method orchestrates the complete analysis pipeline:
        1. Discover data sources
        2. Generate optimized query
        3. Execute query (simulated)
        4. Perform correlation analysis
        5. Analyze time-series trends
        
        Args:
            intent: Security intent to analyze
            context: Query context
            include_correlation: Whether to include correlation analysis
            include_trends: Whether to include trend analysis
            
        Returns:
            Comprehensive analysis results
        """
        try:
            logger.info("Starting comprehensive security data analysis")
            
            # Step 1: Discover data sources
            data_sources = self.discover_security_data_sources()
            if not data_sources:
                return {
                    'error': 'No data sources available for analysis',
                    'data_sources': [],
                    'query': None,
                    'cost_estimate': None,
                    'correlation_data': None,
                    'trends': []
                }
            
            # Step 2: Generate optimized query
            query = self.generate_optimized_query(intent, context, data_sources)
            
            # Step 3: Estimate query cost
            cost_estimate = self.estimate_query_cost(query, data_sources)
            
            # Step 4: Execute query (simulated for now)
            # In a real implementation, this would execute the query via Athena
            primary_results = self._simulate_query_execution(query, data_sources)
            
            analysis_results = {
                'data_sources_found': len(data_sources),
                'data_sources': [
                    {
                        'source_id': ds.source_id,
                        'source_type': ds.source_type.value,
                        'confidence': ds.confidence_score,
                        'size_gb': ds.estimated_size_gb
                    } for ds in data_sources[:5]  # Top 5 sources
                ],
                'query': query,
                'cost_estimate': {
                    'estimated_cost_usd': cost_estimate.estimated_cost_usd,
                    'estimated_data_gb': cost_estimate.estimated_data_scanned_gb,
                    'confidence': cost_estimate.confidence,
                    'within_free_tier': cost_estimate.is_within_free_tier()
                },
                'primary_results': {
                    'row_count': primary_results.row_count,
                    'execution_time_ms': primary_results.execution_time_ms,
                    'data_scanned_gb': primary_results.data_scanned_gb
                }
            }
            
            # Step 5: Correlation analysis (if requested)
            if include_correlation and primary_results.row_count > 0:
                correlated_data = self.execute_correlation_analysis(
                    primary_results, context, data_sources
                )
                
                analysis_results['correlation_data'] = {
                    'correlation_score': correlated_data.correlation_score,
                    'patterns_found': len(correlated_data.correlation_patterns),
                    'patterns': [
                        {
                            'pattern_type': p.pattern_type,
                            'description': p.description,
                            'confidence': p.confidence
                        } for p in correlated_data.correlation_patterns[:5]  # Top 5 patterns
                    ],
                    'related_sources': len(correlated_data.related_data)
                }
                
                # Step 6: Time-series trend analysis (if requested)
                if include_trends:
                    trends = self.analyze_time_series_trends(correlated_data)
                    analysis_results['trends'] = trends[:10]  # Top 10 trends
            else:
                analysis_results['correlation_data'] = None
                analysis_results['trends'] = []
            
            logger.info("Comprehensive analysis completed successfully")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {str(e)}")
            return {
                'error': str(e),
                'data_sources': [],
                'query': None,
                'cost_estimate': None,
                'correlation_data': None,
                'trends': []
            }
    
    def _is_cache_valid(self) -> bool:
        """Check if the data source cache is still valid."""
        if self._cache_timestamp is None:
            return False
        
        cache_age = datetime.now() - self._cache_timestamp
        return cache_age.total_seconds() < (self._cache_ttl_minutes * 60)
    
    def _simulate_query_execution(self, 
                                query: str, 
                                data_sources: List[DataSource]) -> QueryResults:
        """
        Simulate query execution for demonstration purposes.
        
        In a real implementation, this would execute the query via Athena.
        """
        # Simulate execution metrics based on query complexity and data sources
        estimated_rows = sum(ds.estimated_size_gb * 1000 for ds in data_sources[:3])  # Rough estimate
        estimated_rows = min(estimated_rows, 10000)  # Cap at 10k rows
        
        # Simulate execution time based on data size
        total_size_gb = sum(ds.estimated_size_gb for ds in data_sources[:3])
        execution_time_ms = int(total_size_gb * 1000 + 500)  # Base time + size factor
        
        # Generate sample data structure
        sample_data = []
        if estimated_rows > 0:
            # Create sample security event
            sample_data = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'SECURITY_EVENT',
                    'severity': 'MEDIUM',
                    'source_ip': '192.168.1.100',
                    'user_id': 'user123',
                    'action': 'LOGIN_ATTEMPT',
                    'result': 'SUCCESS'
                }
            ]
        
        return QueryResults(
            query_id=f"sim_{hash(query) % 10000:04d}",
            data=sample_data,
            column_names=['timestamp', 'event_type', 'severity', 'source_ip', 'user_id', 'action', 'result'],
            row_count=int(estimated_rows),
            data_scanned_gb=total_size_gb,
            execution_time_ms=execution_time_ms,
            cost_usd=total_size_gb * 0.005,  # Athena pricing
            query_sql=query,
            source_tables=[ds.schema_info.table_name for ds in data_sources[:3]]
        )
    
    def get_optimization_recommendations(self, 
                                       query: str, 
                                       cost_estimate: CostEstimate) -> List[str]:
        """
        Get recommendations for query optimization.
        
        Args:
            query: SQL query to analyze
            cost_estimate: Cost estimate for the query
            
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        try:
            # Check if query is expensive
            if cost_estimate.estimated_cost_usd > 0.01:  # More than 1 cent
                recommendations.append(
                    f"Query cost (${cost_estimate.estimated_cost_usd:.4f}) is above recommended threshold. "
                    "Consider adding more specific time filters or limiting data sources."
                )
            
            # Check for SELECT *
            if "SELECT *" in query.upper():
                recommendations.append(
                    "Query uses SELECT *. Consider selecting only necessary columns to reduce data scanned."
                )
            
            # Check for missing time filters
            if not any(keyword in query.lower() for keyword in ['timestamp', 'date', 'time']):
                recommendations.append(
                    "Query lacks time-based filtering. Adding time constraints can significantly reduce costs."
                )
            
            # Check for partition optimization
            if cost_estimate.estimated_data_scanned_gb > 1.0:
                if 'partition_filtering' not in cost_estimate.factors:
                    recommendations.append(
                        "Large data scan detected. Ensure your query uses partition keys (year, month, day) for better performance."
                    )
            
            # Free tier recommendations
            if not cost_estimate.is_within_free_tier():
                recommendations.append(
                    "Query may exceed AWS Free Tier limits. Consider reducing scope or using data sampling."
                )
            
            if not recommendations:
                recommendations.append("Query appears well-optimized for cost and performance.")
            
        except Exception as e:
            logger.error(f"Error generating optimization recommendations: {str(e)}")
            recommendations.append("Unable to generate optimization recommendations due to analysis error.")
        
        return recommendations