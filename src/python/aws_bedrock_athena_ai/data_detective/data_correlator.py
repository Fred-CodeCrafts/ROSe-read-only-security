"""
Data Correlation component for cross-source event correlation and time-series analysis.
"""

import boto3
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import statistics

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, TimeRange
from aws_bedrock_athena_ai.data_detective.models import (
    DataSource, QueryResults, CorrelatedData, CorrelationPattern,
    DataSourceType
)


logger = logging.getLogger(__name__)


class DataCorrelator:
    """
    Correlates security events across multiple data sources and performs time-series analysis.
    
    This component identifies relationships between events from different sources,
    detects patterns over time, and provides insights into security trends.
    """
    
    def __init__(self, athena_client=None):
        """Initialize the data correlator."""
        self.athena_client = athena_client or boto3.client('athena')
        
        # Correlation algorithms and their weights
        self.correlation_algorithms = {
            'temporal': self._temporal_correlation,
            'ip_based': self._ip_based_correlation,
            'user_based': self._user_based_correlation,
            'system_based': self._system_based_correlation,
            'pattern_based': self._pattern_based_correlation
        }
        
        # Time windows for correlation analysis
        self.correlation_windows = {
            'immediate': timedelta(minutes=5),
            'short_term': timedelta(hours=1),
            'medium_term': timedelta(hours=6),
            'long_term': timedelta(days=1)
        }
    
    def correlate_data_across_sources(self, 
                                    primary_results: QueryResults,
                                    related_sources: List[DataSource],
                                    context: QueryContext) -> CorrelatedData:
        """
        Correlate primary query results with data from related sources.
        
        Args:
            primary_results: Main query results to correlate
            related_sources: Additional data sources to correlate with
            context: Query context for correlation parameters
            
        Returns:
            CorrelatedData with correlation patterns and related data
        """
        try:
            logger.info(f"Starting correlation analysis across {len(related_sources)} sources")
            
            # Extract correlation keys from primary results
            correlation_keys = self._extract_correlation_keys(primary_results)
            
            # Query related sources for correlated data
            related_data = {}
            for source in related_sources:
                try:
                    source_data = self._query_related_source(
                        source, correlation_keys, context
                    )
                    if source_data and source_data.row_count > 0:
                        related_data[source.source_id] = source_data
                except Exception as e:
                    logger.warning(f"Could not query source {source.source_id}: {str(e)}")
            
            # Find correlation patterns
            correlation_patterns = self._find_correlation_patterns(
                primary_results, related_data, context
            )
            
            # Calculate overall correlation score
            correlation_score = self._calculate_correlation_score(correlation_patterns)
            
            logger.info(f"Found {len(correlation_patterns)} correlation patterns")
            
            return CorrelatedData(
                primary_results=primary_results,
                related_data=related_data,
                correlation_patterns=correlation_patterns,
                correlation_score=correlation_score
            )
            
        except Exception as e:
            logger.error(f"Error during correlation analysis: {str(e)}")
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
            trends = []
            
            # Get timeline events
            timeline_events = correlated_data.get_timeline_events()
            
            if not timeline_events:
                return trends
            
            # Group events by time buckets
            window_size = self.correlation_windows.get(time_window, timedelta(hours=1))
            time_buckets = self._group_events_by_time(timeline_events, window_size)
            
            # Analyze trends in each bucket
            for bucket_time, events in time_buckets.items():
                trend_analysis = self._analyze_bucket_trends(bucket_time, events)
                if trend_analysis:
                    trends.append(trend_analysis)
            
            # Detect anomalies and patterns
            anomalies = self._detect_time_series_anomalies(time_buckets)
            trends.extend(anomalies)
            
            logger.info(f"Identified {len(trends)} time-series trends")
            return trends
            
        except Exception as e:
            logger.error(f"Error analyzing time-series trends: {str(e)}")
            return []
    
    def _extract_correlation_keys(self, results: QueryResults) -> Dict[str, List[str]]:
        """Extract keys that can be used for correlation."""
        
        correlation_keys = {
            'ip_addresses': [],
            'user_ids': [],
            'system_ids': [],
            'timestamps': [],
            'event_types': []
        }
        
        for row in results.data:
            # Extract IP addresses
            for ip_field in ['source_ip', 'destination_ip', 'client_ip', 'remote_ip']:
                if ip_field in row and row[ip_field]:
                    correlation_keys['ip_addresses'].append(row[ip_field])
            
            # Extract user IDs
            for user_field in ['user_id', 'username', 'user', 'account']:
                if user_field in row and row[user_field]:
                    correlation_keys['user_ids'].append(row[user_field])
            
            # Extract system IDs
            for system_field in ['system_id', 'hostname', 'host', 'server']:
                if system_field in row and row[system_field]:
                    correlation_keys['system_ids'].append(row[system_field])
            
            # Extract timestamps
            for time_field in ['timestamp', 'time', 'event_time', 'created']:
                if time_field in row and row[time_field]:
                    correlation_keys['timestamps'].append(row[time_field])
            
            # Extract event types
            for event_field in ['event_type', 'action', 'activity', 'operation']:
                if event_field in row and row[event_field]:
                    correlation_keys['event_types'].append(row[event_field])
        
        # Remove duplicates and limit size
        for key in correlation_keys:
            correlation_keys[key] = list(set(correlation_keys[key]))[:100]  # Limit to 100 items
        
        return correlation_keys
    
    def _query_related_source(self, 
                            source: DataSource,
                            correlation_keys: Dict[str, List[str]],
                            context: QueryContext) -> Optional[QueryResults]:
        """Query a related source for correlated data."""
        
        try:
            # Build correlation query
            where_conditions = []
            
            # Add IP-based conditions
            if correlation_keys['ip_addresses']:
                ip_list = "', '".join(correlation_keys['ip_addresses'][:20])  # Limit to 20 IPs
                ip_conditions = []
                for ip_field in ['source_ip', 'destination_ip', 'client_ip']:
                    if source.schema_info.has_column(ip_field):
                        ip_conditions.append(f"{ip_field} IN ('{ip_list}')")
                if ip_conditions:
                    where_conditions.append(f"({' OR '.join(ip_conditions)})")
            
            # Add user-based conditions
            if correlation_keys['user_ids']:
                user_list = "', '".join(correlation_keys['user_ids'][:20])
                user_conditions = []
                for user_field in ['user_id', 'username', 'user']:
                    if source.schema_info.has_column(user_field):
                        user_conditions.append(f"{user_field} IN ('{user_list}')")
                if user_conditions:
                    where_conditions.append(f"({' OR '.join(user_conditions)})")
            
            # Add time-based conditions
            if context.timeframe:
                time_columns = source.schema_info.get_time_columns()
                if time_columns:
                    time_col = time_columns[0]  # Use first time column
                    if context.timeframe.start:
                        where_conditions.append(f"{time_col} >= '{context.timeframe.start.isoformat()}'")
                    if context.timeframe.end:
                        where_conditions.append(f"{time_col} <= '{context.timeframe.end.isoformat()}'")
            
            if not where_conditions:
                return None
            
            # Build and execute query
            columns = source.schema_info.get_column_names()[:10]  # Limit columns
            select_clause = f"SELECT {', '.join(columns)}"
            from_clause = f"FROM {source.schema_info.table_name}"
            where_clause = f"WHERE {' AND '.join(where_conditions)}"
            limit_clause = "LIMIT 1000"  # Limit results for correlation
            
            query = f"{select_clause} {from_clause} {where_clause} {limit_clause}"
            
            # Execute query (simplified - in practice would use Athena client)
            # For now, return mock results
            return QueryResults(
                query_id=f"corr_{source.source_id}",
                data=[],  # Would contain actual query results
                column_names=columns,
                row_count=0,
                data_scanned_gb=0.1,
                execution_time_ms=500,
                cost_usd=0.0005,
                query_sql=query,
                source_tables=[source.schema_info.table_name]
            )
            
        except Exception as e:
            logger.error(f"Error querying related source {source.source_id}: {str(e)}")
            return None
    
    def _find_correlation_patterns(self, 
                                 primary_results: QueryResults,
                                 related_data: Dict[str, QueryResults],
                                 context: QueryContext) -> List[CorrelationPattern]:
        """Find correlation patterns between primary and related data."""
        
        patterns = []
        
        # Apply each correlation algorithm
        for algorithm_name, algorithm_func in self.correlation_algorithms.items():
            try:
                algorithm_patterns = algorithm_func(primary_results, related_data, context)
                patterns.extend(algorithm_patterns)
            except Exception as e:
                logger.warning(f"Error in {algorithm_name} correlation: {str(e)}")
        
        # Sort patterns by confidence and return top patterns
        patterns.sort(key=lambda p: p.confidence, reverse=True)
        return patterns[:20]  # Return top 20 patterns
    
    def _temporal_correlation(self, 
                            primary_results: QueryResults,
                            related_data: Dict[str, QueryResults],
                            context: QueryContext) -> List[CorrelationPattern]:
        """Find temporal correlation patterns."""
        
        patterns = []
        
        # Extract timestamps from primary results
        primary_timestamps = []
        for row in primary_results.data:
            for time_field in ['timestamp', 'time', 'event_time']:
                if time_field in row and row[time_field]:
                    try:
                        if isinstance(row[time_field], str):
                            timestamp = datetime.fromisoformat(row[time_field].replace('Z', '+00:00'))
                        else:
                            timestamp = row[time_field]
                        primary_timestamps.append(timestamp)
                        break
                    except:
                        continue
        
        if not primary_timestamps:
            return patterns
        
        # Check for temporal clustering in related data
        for source_id, results in related_data.items():
            related_timestamps = []
            for row in results.data:
                for time_field in ['timestamp', 'time', 'event_time']:
                    if time_field in row and row[time_field]:
                        try:
                            if isinstance(row[time_field], str):
                                timestamp = datetime.fromisoformat(row[time_field].replace('Z', '+00:00'))
                            else:
                                timestamp = row[time_field]
                            related_timestamps.append(timestamp)
                            break
                        except:
                            continue
            
            if related_timestamps:
                # Check for temporal clustering
                correlation_score = self._calculate_temporal_correlation(
                    primary_timestamps, related_timestamps
                )
                
                if correlation_score > 0.5:  # Threshold for significant correlation
                    pattern = CorrelationPattern(
                        pattern_id=f"temporal_{source_id}",
                        pattern_type="temporal",
                        description=f"Temporal correlation between primary events and {source_id}",
                        confidence=correlation_score,
                        affected_sources=[source_id],
                        time_range=(min(primary_timestamps), max(primary_timestamps))
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _ip_based_correlation(self, 
                            primary_results: QueryResults,
                            related_data: Dict[str, QueryResults],
                            context: QueryContext) -> List[CorrelationPattern]:
        """Find IP-based correlation patterns."""
        
        patterns = []
        
        # Extract IPs from primary results
        primary_ips = set()
        for row in primary_results.data:
            for ip_field in ['source_ip', 'destination_ip', 'client_ip']:
                if ip_field in row and row[ip_field]:
                    primary_ips.add(row[ip_field])
        
        if not primary_ips:
            return patterns
        
        # Check for IP overlap in related data
        for source_id, results in related_data.items():
            related_ips = set()
            for row in results.data:
                for ip_field in ['source_ip', 'destination_ip', 'client_ip']:
                    if ip_field in row and row[ip_field]:
                        related_ips.add(row[ip_field])
            
            if related_ips:
                # Calculate IP overlap
                overlap = primary_ips.intersection(related_ips)
                if overlap:
                    confidence = len(overlap) / min(len(primary_ips), len(related_ips))
                    
                    if confidence > 0.3:  # Threshold for significant overlap
                        pattern = CorrelationPattern(
                            pattern_id=f"ip_{source_id}",
                            pattern_type="ip_based",
                            description=f"IP address correlation: {len(overlap)} shared IPs with {source_id}",
                            confidence=confidence,
                            evidence=[{"shared_ips": list(overlap)[:10]}],  # Limit evidence
                            affected_sources=[source_id]
                        )
                        patterns.append(pattern)
        
        return patterns
    
    def _user_based_correlation(self, 
                              primary_results: QueryResults,
                              related_data: Dict[str, QueryResults],
                              context: QueryContext) -> List[CorrelationPattern]:
        """Find user-based correlation patterns."""
        
        patterns = []
        
        # Extract users from primary results
        primary_users = set()
        for row in primary_results.data:
            for user_field in ['user_id', 'username', 'user']:
                if user_field in row and row[user_field]:
                    primary_users.add(row[user_field])
        
        if not primary_users:
            return patterns
        
        # Check for user overlap in related data
        for source_id, results in related_data.items():
            related_users = set()
            for row in results.data:
                for user_field in ['user_id', 'username', 'user']:
                    if user_field in row and row[user_field]:
                        related_users.add(row[user_field])
            
            if related_users:
                # Calculate user overlap
                overlap = primary_users.intersection(related_users)
                if overlap:
                    confidence = len(overlap) / min(len(primary_users), len(related_users))
                    
                    if confidence > 0.2:  # Threshold for significant overlap
                        pattern = CorrelationPattern(
                            pattern_id=f"user_{source_id}",
                            pattern_type="user_based",
                            description=f"User correlation: {len(overlap)} shared users with {source_id}",
                            confidence=confidence,
                            evidence=[{"shared_users": list(overlap)[:10]}],
                            affected_sources=[source_id]
                        )
                        patterns.append(pattern)
        
        return patterns
    
    def _system_based_correlation(self, 
                                primary_results: QueryResults,
                                related_data: Dict[str, QueryResults],
                                context: QueryContext) -> List[CorrelationPattern]:
        """Find system-based correlation patterns."""
        
        patterns = []
        
        # Extract systems from primary results
        primary_systems = set()
        for row in primary_results.data:
            for system_field in ['system_id', 'hostname', 'host']:
                if system_field in row and row[system_field]:
                    primary_systems.add(row[system_field])
        
        if not primary_systems:
            return patterns
        
        # Check for system overlap in related data
        for source_id, results in related_data.items():
            related_systems = set()
            for row in results.data:
                for system_field in ['system_id', 'hostname', 'host']:
                    if system_field in row and row[system_field]:
                        related_systems.add(row[system_field])
            
            if related_systems:
                # Calculate system overlap
                overlap = primary_systems.intersection(related_systems)
                if overlap:
                    confidence = len(overlap) / min(len(primary_systems), len(related_systems))
                    
                    if confidence > 0.3:  # Threshold for significant overlap
                        pattern = CorrelationPattern(
                            pattern_id=f"system_{source_id}",
                            pattern_type="system_based",
                            description=f"System correlation: {len(overlap)} shared systems with {source_id}",
                            confidence=confidence,
                            evidence=[{"shared_systems": list(overlap)[:10]}],
                            affected_sources=[source_id]
                        )
                        patterns.append(pattern)
        
        return patterns
    
    def _pattern_based_correlation(self, 
                                 primary_results: QueryResults,
                                 related_data: Dict[str, QueryResults],
                                 context: QueryContext) -> List[CorrelationPattern]:
        """Find pattern-based correlations (e.g., similar event sequences)."""
        
        patterns = []
        
        # Extract event patterns from primary results
        primary_patterns = self._extract_event_patterns(primary_results)
        
        if not primary_patterns:
            return patterns
        
        # Check for similar patterns in related data
        for source_id, results in related_data.items():
            related_patterns = self._extract_event_patterns(results)
            
            if related_patterns:
                # Calculate pattern similarity
                similarity_score = self._calculate_pattern_similarity(
                    primary_patterns, related_patterns
                )
                
                if similarity_score > 0.4:  # Threshold for significant similarity
                    pattern = CorrelationPattern(
                        pattern_id=f"pattern_{source_id}",
                        pattern_type="pattern_based",
                        description=f"Event pattern correlation with {source_id}",
                        confidence=similarity_score,
                        affected_sources=[source_id]
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def _calculate_temporal_correlation(self, 
                                      timestamps1: List[datetime],
                                      timestamps2: List[datetime]) -> float:
        """Calculate temporal correlation between two sets of timestamps."""
        
        if not timestamps1 or not timestamps2:
            return 0.0
        
        # Check for temporal clustering within time windows
        correlation_score = 0.0
        total_comparisons = 0
        
        for window_name, window_size in self.correlation_windows.items():
            clustered_pairs = 0
            
            for ts1 in timestamps1:
                for ts2 in timestamps2:
                    total_comparisons += 1
                    if abs((ts1 - ts2).total_seconds()) <= window_size.total_seconds():
                        clustered_pairs += 1
            
            if total_comparisons > 0:
                window_score = clustered_pairs / total_comparisons
                correlation_score = max(correlation_score, window_score)
        
        return min(correlation_score, 1.0)
    
    def _extract_event_patterns(self, results: QueryResults) -> List[str]:
        """Extract event patterns from query results."""
        
        patterns = []
        
        for row in results.data:
            # Create pattern from event type and action
            pattern_parts = []
            
            for field in ['event_type', 'action', 'result']:
                if field in row and row[field]:
                    pattern_parts.append(str(row[field]))
            
            if pattern_parts:
                patterns.append('->'.join(pattern_parts))
        
        return patterns
    
    def _calculate_pattern_similarity(self, 
                                    patterns1: List[str],
                                    patterns2: List[str]) -> float:
        """Calculate similarity between two sets of event patterns."""
        
        if not patterns1 or not patterns2:
            return 0.0
        
        # Calculate Jaccard similarity
        set1 = set(patterns1)
        set2 = set(patterns2)
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_correlation_score(self, patterns: List[CorrelationPattern]) -> float:
        """Calculate overall correlation score from individual patterns."""
        
        if not patterns:
            return 0.0
        
        # Weight patterns by type and confidence
        type_weights = {
            'temporal': 1.0,
            'ip_based': 0.8,
            'user_based': 0.9,
            'system_based': 0.7,
            'pattern_based': 0.6
        }
        
        weighted_scores = []
        for pattern in patterns:
            weight = type_weights.get(pattern.pattern_type, 0.5)
            weighted_scores.append(pattern.confidence * weight)
        
        # Return average weighted score
        return sum(weighted_scores) / len(weighted_scores) if weighted_scores else 0.0
    
    def _group_events_by_time(self, 
                            events: List[Dict[str, Any]], 
                            window_size: timedelta) -> Dict[datetime, List[Dict[str, Any]]]:
        """Group events into time buckets."""
        
        buckets = defaultdict(list)
        
        for event in events:
            timestamp = event.get('timestamp')
            if timestamp:
                # Round timestamp to bucket boundary
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                # Create bucket key (rounded to window size)
                bucket_key = timestamp.replace(
                    minute=0, second=0, microsecond=0
                ) if window_size >= timedelta(hours=1) else timestamp.replace(
                    second=0, microsecond=0
                )
                
                buckets[bucket_key].append(event)
        
        return dict(buckets)
    
    def _analyze_bucket_trends(self, 
                             bucket_time: datetime, 
                             events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze trends within a time bucket."""
        
        if len(events) < 2:
            return None
        
        # Count events by type
        event_counts = defaultdict(int)
        for event in events:
            event_type = event.get('data', {}).get('event_type', 'unknown')
            event_counts[event_type] += 1
        
        # Identify dominant event types
        total_events = len(events)
        dominant_types = {
            event_type: count for event_type, count in event_counts.items()
            if count / total_events > 0.1  # More than 10% of events
        }
        
        if dominant_types:
            return {
                'bucket_time': bucket_time,
                'total_events': total_events,
                'dominant_event_types': dominant_types,
                'trend_type': 'event_clustering',
                'confidence': max(count / total_events for count in dominant_types.values())
            }
        
        return None
    
    def _detect_time_series_anomalies(self, 
                                    time_buckets: Dict[datetime, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Detect anomalies in time-series data."""
        
        anomalies = []
        
        if len(time_buckets) < 3:
            return anomalies
        
        # Calculate event counts per bucket
        bucket_counts = [(bucket_time, len(events)) for bucket_time, events in time_buckets.items()]
        bucket_counts.sort(key=lambda x: x[0])  # Sort by time
        
        counts = [count for _, count in bucket_counts]
        
        # Calculate statistics
        mean_count = statistics.mean(counts)
        stdev_count = statistics.stdev(counts) if len(counts) > 1 else 0
        
        # Detect anomalies (values > 2 standard deviations from mean)
        threshold = mean_count + (2 * stdev_count)
        
        for bucket_time, count in bucket_counts:
            if count > threshold and stdev_count > 0:
                anomalies.append({
                    'anomaly_time': bucket_time,
                    'event_count': count,
                    'expected_count': mean_count,
                    'anomaly_type': 'event_spike',
                    'severity': 'high' if count > mean_count + (3 * stdev_count) else 'medium',
                    'confidence': min((count - mean_count) / (3 * stdev_count), 1.0) if stdev_count > 0 else 0.5
                })
        
        return anomalies