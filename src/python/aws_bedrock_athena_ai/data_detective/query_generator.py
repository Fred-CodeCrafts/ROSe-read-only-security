"""
Query Generation component for converting security intents into optimized Athena SQL queries.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, SecurityIntentType, EntityType, TimeRange
from aws_bedrock_athena_ai.data_detective.models import DataSource, QueryResults, CostEstimate, DataSourceType


logger = logging.getLogger(__name__)


class QueryGenerator:
    """
    Converts security intents into efficient Athena SQL queries.
    
    This component takes natural language security intents and generates
    optimized SQL queries that minimize cost while maximizing relevance.
    """
    
    def __init__(self):
        """Initialize the query generator."""
        # Cost per GB scanned in Athena (as of 2024)
        self.athena_cost_per_gb = 0.005  # $5 per TB
        
        # Query templates for different security intents
        self.query_templates = {
            SecurityIntentType.THREAT_HUNTING: self._generate_threat_hunting_query,
            SecurityIntentType.COMPLIANCE_CHECK: self._generate_compliance_query,
            SecurityIntentType.RISK_ASSESSMENT: self._generate_risk_assessment_query,
            SecurityIntentType.INCIDENT_INVESTIGATION: self._generate_incident_investigation_query,
            SecurityIntentType.VULNERABILITY_SCAN: self._generate_vulnerability_query,
            SecurityIntentType.ACCESS_REVIEW: self._generate_access_review_query,
            SecurityIntentType.ANOMALY_DETECTION: self._generate_anomaly_detection_query,
            SecurityIntentType.SECURITY_POSTURE: self._generate_security_posture_query
        }
    
    def generate_optimized_query(self, 
                               intent: SecurityIntent, 
                               context: QueryContext,
                               available_sources: List[DataSource]) -> str:
        """
        Generate an optimized Athena SQL query based on security intent and context.
        
        Args:
            intent: The recognized security intent
            context: Query context with timeframes, systems, etc.
            available_sources: List of available data sources
            
        Returns:
            Optimized SQL query string
        """
        try:
            # Select the most relevant data sources
            relevant_sources = self._select_relevant_sources(intent, context, available_sources)
            
            if not relevant_sources:
                raise ValueError("No relevant data sources found for this query")
            
            # Generate base query using intent-specific template
            if intent.intent_type in self.query_templates:
                query = self.query_templates[intent.intent_type](
                    intent, context, relevant_sources
                )
            else:
                # Fallback to generic security query
                query = self._generate_generic_security_query(
                    intent, context, relevant_sources
                )
            
            # Apply optimizations
            optimized_query = self._optimize_query(query, context, relevant_sources)
            
            logger.info(f"Generated optimized query for intent: {intent.intent_type}")
            return optimized_query
            
        except Exception as e:
            logger.error(f"Error generating query: {str(e)}")
            raise
    
    def estimate_query_cost(self, 
                          query: str, 
                          data_sources: List[DataSource]) -> CostEstimate:
        """
        Estimate the cost of executing a query.
        
        Args:
            query: SQL query to estimate
            data_sources: Data sources involved in the query
            
        Returns:
            Cost estimate with confidence level
        """
        try:
            # Parse query to identify tables and filters
            tables_used = self._extract_tables_from_query(query)
            has_time_filter = self._has_time_based_filter(query)
            has_partition_filter = self._has_partition_filter(query)
            
            total_estimated_gb = 0.0
            confidence_factors = []
            
            for source in data_sources:
                if any(table in source.schema_info.table_name for table in tables_used):
                    # Base estimate from source size
                    estimated_gb = source.estimated_size_gb
                    
                    # Apply reduction factors for optimizations
                    if has_time_filter and source.is_time_partitioned():
                        # Time-based partitioning can reduce scan by ~90%
                        estimated_gb *= 0.1
                        confidence_factors.append("time_partitioning")
                    
                    if has_partition_filter:
                        # Additional partition filters reduce scan further
                        estimated_gb *= 0.5
                        confidence_factors.append("partition_filtering")
                    
                    # Column selection optimization
                    selected_columns = self._count_selected_columns(query)
                    total_columns = len(source.schema_info.columns)
                    if total_columns > 0:
                        column_ratio = min(selected_columns / total_columns, 1.0)
                        estimated_gb *= column_ratio
                        confidence_factors.append("column_selection")
                    
                    total_estimated_gb += estimated_gb
            
            # Calculate cost
            estimated_cost = total_estimated_gb * self.athena_cost_per_gb
            
            # Confidence based on available information
            confidence = 0.8 if confidence_factors else 0.5
            
            return CostEstimate(
                estimated_data_scanned_gb=total_estimated_gb,
                estimated_cost_usd=estimated_cost,
                confidence=confidence,
                factors=confidence_factors
            )
            
        except Exception as e:
            logger.error(f"Error estimating query cost: {str(e)}")
            return CostEstimate(
                estimated_data_scanned_gb=0.0,
                estimated_cost_usd=0.0,
                confidence=0.0,
                factors=[f"estimation_error: {str(e)}"]
            )
    
    def _select_relevant_sources(self, 
                               intent: SecurityIntent, 
                               context: QueryContext,
                               available_sources: List[DataSource]) -> List[DataSource]:
        """Select the most relevant data sources for the given intent and context."""
        
        # Map intent types to preferred data source types
        intent_source_mapping = {
            SecurityIntentType.THREAT_HUNTING: [
                DataSourceType.SECURITY_LOGS, 
                DataSourceType.NETWORK_TRAFFIC,
                DataSourceType.FIREWALL_LOGS
            ],
            SecurityIntentType.ACCESS_REVIEW: [
                DataSourceType.ACCESS_LOGS,
                DataSourceType.CLOUDTRAIL_LOGS,
                DataSourceType.SECURITY_LOGS
            ],
            SecurityIntentType.COMPLIANCE_CHECK: [
                DataSourceType.SYSTEM_CONFIGS,
                DataSourceType.CLOUDTRAIL_LOGS,
                DataSourceType.ACCESS_LOGS
            ],
            SecurityIntentType.VULNERABILITY_SCAN: [
                DataSourceType.VULNERABILITY_SCANS,
                DataSourceType.SYSTEM_CONFIGS
            ],
            SecurityIntentType.INCIDENT_INVESTIGATION: [
                DataSourceType.SECURITY_LOGS,
                DataSourceType.NETWORK_TRAFFIC,
                DataSourceType.CLOUDTRAIL_LOGS,
                DataSourceType.ACCESS_LOGS
            ],
            SecurityIntentType.RISK_ASSESSMENT: [
                DataSourceType.SECURITY_LOGS,
                DataSourceType.SYSTEM_CONFIGS,
                DataSourceType.VULNERABILITY_SCANS
            ],
            SecurityIntentType.ANOMALY_DETECTION: [
                DataSourceType.SECURITY_LOGS,
                DataSourceType.NETWORK_TRAFFIC,
                DataSourceType.ACCESS_LOGS
            ],
            SecurityIntentType.SECURITY_POSTURE: [
                DataSourceType.SYSTEM_CONFIGS,
                DataSourceType.VULNERABILITY_SCANS,
                DataSourceType.COMPLIANCE_REPORTS
            ]
        }
        
        relevant_sources = []
        preferred_types = intent_source_mapping.get(intent.intent_type, [])
        
        # First, add sources that match preferred types
        for source in available_sources:
            if source.source_type in preferred_types:
                relevant_sources.append(source)
        
        # If no preferred sources found, add any security-related sources
        if not relevant_sources:
            for source in available_sources:
                if self._is_security_related(source):
                    relevant_sources.append(source)
        
        # Filter by context constraints (systems, timeframes, etc.)
        if context.systems:
            relevant_sources = [
                source for source in relevant_sources
                if any(system in source.schema_info.table_name.lower() 
                      for system in [s.lower() for s in context.systems])
            ]
        
        # Sort by relevance score (size, freshness, completeness)
        relevant_sources.sort(key=lambda s: self._calculate_source_relevance(s, intent, context), reverse=True)
        
        # Limit to top sources to control cost
        max_sources = 5 if context.priority_level == "high" else 3
        return relevant_sources[:max_sources]
    
    def _is_security_related(self, source: DataSource) -> bool:
        """Check if a data source contains security-related data."""
        security_keywords = [
            'security', 'auth', 'login', 'access', 'firewall', 'intrusion',
            'threat', 'malware', 'vulnerability', 'incident', 'alert',
            'cloudtrail', 'guardduty', 'waf', 'vpc', 'flow'
        ]
        
        source_name = source.schema_info.table_name.lower()
        return any(keyword in source_name for keyword in security_keywords)
    
    def _calculate_source_relevance(self, 
                                  source: DataSource, 
                                  intent: SecurityIntent, 
                                  context: QueryContext) -> float:
        """Calculate relevance score for a data source."""
        score = 0.0
        
        # Base score from source type match
        preferred_types = {
            SecurityIntentType.THREAT_HUNTING: [DataSourceType.SECURITY_LOGS, DataSourceType.NETWORK_TRAFFIC],
            SecurityIntentType.ACCESS_REVIEW: [DataSourceType.ACCESS_LOGS, DataSourceType.CLOUDTRAIL_LOGS],
            SecurityIntentType.COMPLIANCE_CHECK: [DataSourceType.SYSTEM_CONFIGS, DataSourceType.COMPLIANCE_REPORTS]
        }.get(intent.intent_type, [])
        
        if source.source_type in preferred_types:
            score += 10.0
        
        # Freshness score (more recent data is more relevant)
        if hasattr(source, 'last_updated'):
            days_old = (datetime.now() - source.last_updated).days
            freshness_score = max(0, 10 - (days_old / 7))  # Decay over weeks
            score += freshness_score
        
        # Size penalty (smaller sources are easier to query)
        if source.estimated_size_gb < 1.0:
            score += 2.0
        elif source.estimated_size_gb > 10.0:
            score -= 1.0
        
        # Entity match bonus
        for entity in intent.entities:
            if entity.lower() in source.schema_info.table_name.lower():
                score += 5.0
        
        return score
   
    
    def _generate_threat_hunting_query(self, 
                                     intent: SecurityIntent, 
                                     context: QueryContext,
                                     sources: List[DataSource]) -> str:
        """Generate SQL query for threat hunting scenarios."""
        
        # Build base query structure
        select_clause = self._build_select_clause(sources, [
            'timestamp', 'source_ip', 'destination_ip', 'user_id', 
            'event_type', 'action', 'result', 'severity'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        # Add threat-specific conditions
        threat_conditions = []
        
        # Look for suspicious activities
        threat_conditions.extend([
            "result = 'FAILED' OR result = 'DENIED'",
            "severity IN ('HIGH', 'CRITICAL')",
            "event_type LIKE '%INTRUSION%' OR event_type LIKE '%MALWARE%'"
        ])
        
        # Add entity-specific filters
        for entity in intent.entities:
            if self._is_ip_address(entity):
                threat_conditions.append(f"(source_ip = '{entity}' OR destination_ip = '{entity}')")
            elif self._is_user_identifier(entity):
                threat_conditions.append(f"user_id LIKE '%{entity}%'")
            else:
                # Generic text search
                threat_conditions.append(f"(event_type LIKE '%{entity}%' OR action LIKE '%{entity}%')")
        
        if threat_conditions:
            where_conditions.append(f"({' OR '.join(threat_conditions)})")
        
        # Build final query
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY timestamp DESC"
        limit_clause = f"LIMIT {self._get_result_limit(context)}"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        {limit_clause}
        """.strip()
        
        return query
    
    def _generate_compliance_query(self, 
                                 intent: SecurityIntent, 
                                 context: QueryContext,
                                 sources: List[DataSource]) -> str:
        """Generate SQL query for compliance checking."""
        
        select_clause = self._build_select_clause(sources, [
            'system_id', 'config_type', 'setting_name', 'setting_value',
            'compliance_status', 'last_modified'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Focus on non-compliant configurations
        where_conditions.append("compliance_status != 'COMPLIANT'")
        
        # Add system-specific filters
        if context.systems:
            system_filter = " OR ".join([f"system_id LIKE '%{system}%'" for system in context.systems])
            where_conditions.append(f"({system_filter})")
        
        # Add entity-specific compliance checks
        for entity in intent.entities:
            if entity.upper() in ['PCI', 'HIPAA', 'SOX', 'GDPR']:
                where_conditions.append(f"config_type LIKE '%{entity}%'")
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY last_modified DESC"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        """.strip()
        
        return query
    
    def _generate_risk_assessment_query(self, 
                                      intent: SecurityIntent, 
                                      context: QueryContext,
                                      sources: List[DataSource]) -> str:
        """Generate SQL query for risk assessment."""
        
        # Combine multiple source types for comprehensive risk view
        select_clause = """
        SELECT 
            COALESCE(s.timestamp, v.scan_date, c.last_modified) as event_time,
            COALESCE(s.severity, v.severity, 'MEDIUM') as risk_level,
            s.event_type as security_event,
            v.vulnerability_type,
            c.compliance_status,
            s.affected_systems,
            v.cvss_score
        """
        
        from_clause = self._build_multi_source_from_clause(sources)
        
        where_conditions = []
        
        # Focus on high-risk items
        where_conditions.extend([
            "(s.severity IN ('HIGH', 'CRITICAL') OR v.cvss_score > 7.0 OR c.compliance_status = 'NON_COMPLIANT')"
        ])
        
        # Add time filtering
        if context.timeframe:
            time_condition = self._build_multi_source_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY risk_level DESC, event_time DESC"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        """.strip()
        
        return query
    
    def _generate_incident_investigation_query(self, 
                                             intent: SecurityIntent, 
                                             context: QueryContext,
                                             sources: List[DataSource]) -> str:
        """Generate SQL query for incident investigation."""
        
        select_clause = self._build_select_clause(sources, [
            'timestamp', 'event_id', 'source_ip', 'destination_ip', 
            'user_id', 'event_type', 'action', 'result', 'raw_log'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering (usually narrow for incidents)
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        # Add incident-specific filters based on entities
        incident_conditions = []
        for entity in intent.entities:
            if self._is_ip_address(entity):
                incident_conditions.append(f"(source_ip = '{entity}' OR destination_ip = '{entity}')")
            elif self._is_user_identifier(entity):
                incident_conditions.append(f"user_id = '{entity}'")
            elif entity.startswith('INC-') or entity.startswith('INCIDENT-'):
                # Incident ID search
                incident_conditions.append(f"event_id LIKE '%{entity}%'")
        
        if incident_conditions:
            where_conditions.append(f"({' OR '.join(incident_conditions)})")
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY timestamp ASC"  # Chronological for incident timeline
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        """.strip()
        
        return query
    
    def _generate_vulnerability_query(self, 
                                    intent: SecurityIntent, 
                                    context: QueryContext,
                                    sources: List[DataSource]) -> str:
        """Generate SQL query for vulnerability scanning results."""
        
        select_clause = self._build_select_clause(sources, [
            'scan_date', 'system_id', 'vulnerability_id', 'vulnerability_type',
            'severity', 'cvss_score', 'description', 'remediation_status'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Focus on unpatched vulnerabilities
        where_conditions.append("remediation_status != 'FIXED'")
        
        # Add severity filtering
        where_conditions.append("severity IN ('HIGH', 'CRITICAL') OR cvss_score > 7.0")
        
        # Add system-specific filters
        if context.systems:
            system_filter = " OR ".join([f"system_id LIKE '%{system}%'" for system in context.systems])
            where_conditions.append(f"({system_filter})")
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY cvss_score DESC, scan_date DESC"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        """.strip()
        
        return query
    
    def _generate_access_review_query(self, 
                                    intent: SecurityIntent, 
                                    context: QueryContext,
                                    sources: List[DataSource]) -> str:
        """Generate SQL query for access review and analysis."""
        
        select_clause = self._build_select_clause(sources, [
            'timestamp', 'user_id', 'resource', 'action', 'result',
            'source_ip', 'user_agent', 'session_id'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        # Focus on access-related events
        access_conditions = [
            "action IN ('LOGIN', 'LOGOUT', 'ACCESS', 'PERMISSION_CHANGE')",
            "event_type LIKE '%ACCESS%' OR event_type LIKE '%AUTH%'"
        ]
        where_conditions.append(f"({' OR '.join(access_conditions)})")
        
        # Add user-specific filters
        for entity in intent.entities:
            if self._is_user_identifier(entity):
                where_conditions.append(f"user_id LIKE '%{entity}%'")
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY timestamp DESC"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        """.strip()
        
        return query
    
    def _generate_anomaly_detection_query(self, 
                                        intent: SecurityIntent, 
                                        context: QueryContext,
                                        sources: List[DataSource]) -> str:
        """Generate SQL query for anomaly detection."""
        
        # Use window functions to detect anomalies
        select_clause = """
        SELECT 
            timestamp,
            user_id,
            source_ip,
            event_type,
            action,
            COUNT(*) OVER (PARTITION BY user_id ORDER BY timestamp RANGE INTERVAL '1' HOUR PRECEDING) as events_per_hour,
            COUNT(DISTINCT source_ip) OVER (PARTITION BY user_id ORDER BY timestamp RANGE INTERVAL '1' DAY PRECEDING) as unique_ips_per_day,
            LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) as prev_event_time
        """
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        
        # Wrap in outer query to filter anomalies
        inner_query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        """
        
        query = f"""
        SELECT * FROM (
            {inner_query}
        ) anomaly_data
        WHERE events_per_hour > 50 
           OR unique_ips_per_day > 10
           OR EXTRACT(EPOCH FROM (timestamp - prev_event_time)) < 1
        ORDER BY timestamp DESC
        """.strip()
        
        return query
    
    def _generate_security_posture_query(self, 
                                       intent: SecurityIntent, 
                                       context: QueryContext,
                                       sources: List[DataSource]) -> str:
        """Generate SQL query for overall security posture assessment."""
        
        # Aggregate query across multiple security dimensions
        select_clause = """
        SELECT 
            'Security Events' as category,
            COUNT(*) as total_count,
            COUNT(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 END) as high_risk_count,
            MAX(timestamp) as latest_event
        """
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering (typically last 30 days for posture)
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
        else:
            # Default to last 30 days
            time_condition = "timestamp >= CURRENT_DATE - INTERVAL '30' DAY"
        where_conditions.append(time_condition)
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        """.strip()
        
        return query
    
    def _generate_generic_security_query(self, 
                                       intent: SecurityIntent, 
                                       context: QueryContext,
                                       sources: List[DataSource]) -> str:
        """Generate a generic security query when no specific template matches."""
        
        select_clause = self._build_select_clause(sources, [
            'timestamp', 'event_type', 'severity', 'description', 'source_system'
        ])
        
        from_clause = self._build_from_clause(sources)
        where_conditions = []
        
        # Add time-based filtering
        if context.timeframe:
            time_condition = self._build_time_filter(context.timeframe)
            where_conditions.append(time_condition)
        
        # Add entity-based filtering
        if intent.entities:
            entity_conditions = []
            for entity in intent.entities:
                entity_conditions.append(f"description LIKE '%{entity}%'")
            where_conditions.append(f"({' OR '.join(entity_conditions)})")
        
        where_clause = f"WHERE {' AND '.join(where_conditions)}" if where_conditions else ""
        order_clause = "ORDER BY timestamp DESC"
        limit_clause = f"LIMIT {self._get_result_limit(context)}"
        
        query = f"""
        {select_clause}
        {from_clause}
        {where_clause}
        {order_clause}
        {limit_clause}
        """.strip()
        
        return query
    
    def _optimize_query(self, 
                       query: str, 
                       context: QueryContext,
                       sources: List[DataSource]) -> str:
        """Apply various optimizations to reduce query cost and improve performance."""
        
        optimized_query = query
        
        # 1. Add partition pruning
        optimized_query = self._add_partition_pruning(optimized_query, context, sources)
        
        # 2. Optimize column selection
        optimized_query = self._optimize_column_selection(optimized_query, sources)
        
        # 3. Add query hints for performance
        optimized_query = self._add_query_hints(optimized_query)
        
        # 4. Validate and clean up query
        optimized_query = self._clean_query(optimized_query)
        
        return optimized_query
    
    def _add_partition_pruning(self, 
                             query: str, 
                             context: QueryContext,
                             sources: List[DataSource]) -> str:
        """Add partition pruning to reduce data scanned."""
        
        # Find WHERE clause or add one
        if "WHERE" not in query.upper():
            # Add WHERE clause before ORDER BY or at the end
            if "ORDER BY" in query.upper():
                query = query.replace("ORDER BY", "WHERE 1=1 ORDER BY")
            else:
                query += " WHERE 1=1"
        
        # Add partition filters for each partitioned source
        for source in sources:
            if source.is_time_partitioned():
                # Add year/month/day partition filters
                if context.timeframe and context.timeframe.start_time:
                    start_date = context.timeframe.start_time
                    end_date = context.timeframe.end_time or datetime.now()
                    
                    # Add partition filters
                    partition_filter = f"""
                    AND year >= '{start_date.year}' 
                    AND year <= '{end_date.year}'
                    AND month >= '{start_date.month:02d}' 
                    AND month <= '{end_date.month:02d}'
                    """
                    
                    query = query.replace("WHERE", f"WHERE{partition_filter} AND")
        
        return query
    
    def _optimize_column_selection(self, query: str, sources: List[DataSource]) -> str:
        """Optimize column selection to reduce data scanned."""
        
        # If using SELECT *, replace with specific columns
        if "SELECT *" in query.upper():
            # Get essential columns for security analysis
            essential_columns = [
                'timestamp', 'event_type', 'severity', 'source_ip', 
                'user_id', 'action', 'result'
            ]
            
            # Find available columns from sources
            available_columns = []
            for source in sources:
                for column in source.schema_info.columns:
                    if column.name.lower() in [col.lower() for col in essential_columns]:
                        available_columns.append(column.name)
            
            if available_columns:
                column_list = ", ".join(available_columns)
                query = query.replace("SELECT *", f"SELECT {column_list}")
        
        return query
    
    def _add_query_hints(self, query: str) -> str:
        """Add Athena-specific query hints for better performance."""
        
        # Add hints for large table joins
        if "JOIN" in query.upper():
            # Use broadcast join hint for small dimension tables
            query = f"/* BROADCAST_JOIN */ {query}"
        
        # Add compression hint
        query = f"/* COMPRESSION=GZIP */ {query}"
        
        return query
    
    def _clean_query(self, query: str) -> str:
        """Clean up and validate the query."""
        
        # Remove extra whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        # Ensure proper SQL formatting
        query = query.replace(' ,', ',').replace('( ', '(').replace(' )', ')')
        
        return query
    
    def _build_select_clause(self, sources: List[DataSource], preferred_columns: List[str]) -> str:
        """Build SELECT clause with available columns."""
        
        available_columns = []
        
        for source in sources:
            for column in source.schema_info.columns:
                if column.name.lower() in [col.lower() for col in preferred_columns]:
                    available_columns.append(column.name)
        
        if not available_columns:
            # Fallback to all columns
            available_columns = ['*']
        
        return f"SELECT {', '.join(available_columns)}"
    
    def _build_from_clause(self, sources: List[DataSource]) -> str:
        """Build FROM clause with source tables."""
        
        if len(sources) == 1:
            return f"FROM {sources[0].schema_info.table_name}"
        
        # Multiple sources - use UNION ALL
        union_parts = []
        for source in sources:
            union_parts.append(f"SELECT * FROM {source.schema_info.table_name}")
        
        return f"FROM ({' UNION ALL '.join(union_parts)}) combined_sources"
    
    def _build_multi_source_from_clause(self, sources: List[DataSource]) -> str:
        """Build FROM clause for multi-source joins."""
        
        # Identify different source types
        security_logs = [s for s in sources if s.source_type == DataSourceType.SECURITY_LOGS]
        vuln_scans = [s for s in sources if s.source_type == DataSourceType.VULNERABILITY_SCANS]
        configs = [s for s in sources if s.source_type == DataSourceType.SYSTEM_CONFIGS]
        
        from_parts = []
        
        if security_logs:
            from_parts.append(f"{security_logs[0].schema_info.table_name} s")
        
        if vuln_scans:
            if from_parts:
                from_parts.append(f"FULL OUTER JOIN {vuln_scans[0].schema_info.table_name} v ON s.system_id = v.system_id")
            else:
                from_parts.append(f"{vuln_scans[0].schema_info.table_name} v")
        
        if configs:
            if from_parts:
                from_parts.append(f"FULL OUTER JOIN {configs[0].schema_info.table_name} c ON COALESCE(s.system_id, v.system_id) = c.system_id")
            else:
                from_parts.append(f"{configs[0].schema_info.table_name} c")
        
        return f"FROM {' '.join(from_parts)}" if from_parts else "FROM dual"
    
    def _build_time_filter(self, timeframe: TimeRange) -> str:
        """Build time-based WHERE condition."""
        
        if not timeframe:
            return "1=1"
        
        conditions = []
        
        if timeframe.start:
            conditions.append(f"timestamp >= '{timeframe.start.isoformat()}'")
        
        if timeframe.end:
            conditions.append(f"timestamp <= '{timeframe.end.isoformat()}'")
        
        return " AND ".join(conditions) if conditions else "1=1"
    
    def _build_multi_source_time_filter(self, timeframe) -> str:
        """Build time filter for multi-source queries."""
        
        if not timeframe:
            return "1=1"
        
        conditions = []
        
        if timeframe.start_time:
            time_condition = f"'{timeframe.start_time.isoformat()}'"
            conditions.append(f"(s.timestamp >= {time_condition} OR v.scan_date >= {time_condition} OR c.last_modified >= {time_condition})")
        
        if timeframe.end_time:
            time_condition = f"'{timeframe.end_time.isoformat()}'"
            conditions.append(f"(s.timestamp <= {time_condition} OR v.scan_date <= {time_condition} OR c.last_modified <= {time_condition})")
        
        return " AND ".join(conditions) if conditions else "1=1"
    
    def _get_result_limit(self, context: QueryContext) -> int:
        """Get appropriate result limit based on context."""
        
        if context.priority_level == "high":
            return 10000
        elif context.priority_level == "medium":
            return 5000
        else:
            return 1000
    
    def _extract_tables_from_query(self, query: str) -> List[str]:
        """Extract table names from SQL query."""
        
        # Simple regex to find table names after FROM and JOIN
        table_pattern = r'(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(table_pattern, query, re.IGNORECASE)
        return matches
    
    def _has_time_based_filter(self, query: str) -> bool:
        """Check if query has time-based filtering."""
        
        time_keywords = ['timestamp', 'date', 'time', 'created', 'modified']
        query_lower = query.lower()
        
        return any(keyword in query_lower for keyword in time_keywords)
    
    def _has_partition_filter(self, query: str) -> bool:
        """Check if query has partition-based filtering."""
        
        partition_keywords = ['year', 'month', 'day', 'partition']
        query_lower = query.lower()
        
        return any(keyword in query_lower for keyword in partition_keywords)
    
    def _count_selected_columns(self, query: str) -> int:
        """Count the number of columns selected in the query."""
        
        if "SELECT *" in query.upper():
            return 10  # Estimate for SELECT *
        
        # Extract SELECT clause
        select_match = re.search(r'SELECT\s+(.*?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
        if select_match:
            select_clause = select_match.group(1)
            # Count commas + 1 for column count
            return select_clause.count(',') + 1
        
        return 5  # Default estimate
    
    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address."""
        
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, text))
    
    def _is_user_identifier(self, text: str) -> bool:
        """Check if text looks like a user identifier."""
        
        # Common user ID patterns
        user_patterns = [
            r'^[a-zA-Z][a-zA-Z0-9._-]*$',  # Standard username
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
            r'^[A-Z]{2,}\\[a-zA-Z][a-zA-Z0-9._-]*$'  # Domain\username
        ]
        
        return any(re.match(pattern, text) for pattern in user_patterns)