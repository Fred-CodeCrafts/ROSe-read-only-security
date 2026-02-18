"""
Demonstration of cross-source data correlation capabilities.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any

from aws_bedrock_athena_ai.nlp.models import SecurityIntent, QueryContext, SecurityIntentType, TimeRange
from aws_bedrock_athena_ai.data_detective.models import DataSource, DataSourceType, SchemaInfo, ColumnInfo, QueryResults
from aws_bedrock_athena_ai.data_detective.data_correlator import DataCorrelator
from aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective


def create_sample_security_data() -> Dict[str, QueryResults]:
    """Create sample security data for correlation demonstration."""
    
    # Sample firewall logs
    firewall_data = QueryResults(
        query_id="fw_001",
        data=[
            {
                'timestamp': '2024-01-15T10:00:00Z',
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.5',
                'action': 'ALLOW',
                'port': '443',
                'protocol': 'TCP'
            },
            {
                'timestamp': '2024-01-15T10:01:00Z',
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.10',
                'action': 'DENY',
                'port': '22',
                'protocol': 'TCP'
            },
            {
                'timestamp': '2024-01-15T10:05:00Z',
                'source_ip': '203.0.113.50',
                'destination_ip': '10.0.0.5',
                'action': 'DENY',
                'port': '80',
                'protocol': 'TCP'
            }
        ],
        column_names=['timestamp', 'source_ip', 'destination_ip', 'action', 'port', 'protocol'],
        row_count=3,
        data_scanned_gb=0.1,
        execution_time_ms=200,
        cost_usd=0.0005,
        query_sql="SELECT * FROM firewall_logs WHERE timestamp >= '2024-01-15T10:00:00Z'",
        source_tables=['firewall_logs']
    )
    
    # Sample access logs
    access_data = QueryResults(
        query_id="access_001",
        data=[
            {
                'timestamp': '2024-01-15T10:00:30Z',
                'user_id': 'user123',
                'source_ip': '192.168.1.100',
                'resource': '/api/login',
                'method': 'POST',
                'status_code': '200',
                'user_agent': 'Mozilla/5.0'
            },
            {
                'timestamp': '2024-01-15T10:01:15Z',
                'user_id': 'user123',
                'source_ip': '192.168.1.100',
                'resource': '/api/data',
                'method': 'GET',
                'status_code': '200',
                'user_agent': 'Mozilla/5.0'
            },
            {
                'timestamp': '2024-01-15T10:05:30Z',
                'user_id': 'admin',
                'source_ip': '203.0.113.50',
                'resource': '/admin/login',
                'method': 'POST',
                'status_code': '401',
                'user_agent': 'curl/7.68.0'
            }
        ],
        column_names=['timestamp', 'user_id', 'source_ip', 'resource', 'method', 'status_code', 'user_agent'],
        row_count=3,
        data_scanned_gb=0.05,
        execution_time_ms=150,
        cost_usd=0.00025,
        query_sql="SELECT * FROM access_logs WHERE timestamp >= '2024-01-15T10:00:00Z'",
        source_tables=['access_logs']
    )
    
    # Sample system events
    system_data = QueryResults(
        query_id="sys_001",
        data=[
            {
                'timestamp': '2024-01-15T10:00:45Z',
                'system_id': 'web-server-01',
                'event_type': 'USER_LOGIN',
                'user_id': 'user123',
                'severity': 'INFO',
                'description': 'User login successful'
            },
            {
                'timestamp': '2024-01-15T10:05:45Z',
                'system_id': 'web-server-01',
                'event_type': 'FAILED_LOGIN',
                'user_id': 'admin',
                'severity': 'WARNING',
                'description': 'Failed login attempt from external IP'
            },
            {
                'timestamp': '2024-01-15T10:06:00Z',
                'system_id': 'web-server-01',
                'event_type': 'BRUTE_FORCE_DETECTED',
                'user_id': 'admin',
                'severity': 'HIGH',
                'description': 'Multiple failed login attempts detected'
            }
        ],
        column_names=['timestamp', 'system_id', 'event_type', 'user_id', 'severity', 'description'],
        row_count=3,
        data_scanned_gb=0.02,
        execution_time_ms=100,
        cost_usd=0.0001,
        query_sql="SELECT * FROM system_events WHERE timestamp >= '2024-01-15T10:00:00Z'",
        source_tables=['system_events']
    )
    
    return {
        'firewall_logs': firewall_data,
        'access_logs': access_data,
        'system_events': system_data
    }


def create_sample_data_sources() -> List[DataSource]:
    """Create sample data sources for correlation demonstration."""
    
    sources = [
        DataSource(
            source_id="firewall_001",
            source_type=DataSourceType.FIREWALL_LOGS,
            s3_location="s3://security-bucket/firewall-logs/",
            schema_info=SchemaInfo(
                table_name="firewall_logs",
                columns=[
                    ColumnInfo("timestamp", "timestamp"),
                    ColumnInfo("source_ip", "string"),
                    ColumnInfo("destination_ip", "string"),
                    ColumnInfo("action", "string"),
                    ColumnInfo("port", "string"),
                    ColumnInfo("protocol", "string")
                ]
            ),
            confidence_score=0.95,
            estimated_size_gb=2.1
        ),
        DataSource(
            source_id="access_001",
            source_type=DataSourceType.ACCESS_LOGS,
            s3_location="s3://security-bucket/access-logs/",
            schema_info=SchemaInfo(
                table_name="access_logs",
                columns=[
                    ColumnInfo("timestamp", "timestamp"),
                    ColumnInfo("user_id", "string"),
                    ColumnInfo("source_ip", "string"),
                    ColumnInfo("resource", "string"),
                    ColumnInfo("method", "string"),
                    ColumnInfo("status_code", "string"),
                    ColumnInfo("user_agent", "string")
                ]
            ),
            confidence_score=0.90,
            estimated_size_gb=1.8
        ),
        DataSource(
            source_id="system_001",
            source_type=DataSourceType.SECURITY_LOGS,
            s3_location="s3://security-bucket/system-events/",
            schema_info=SchemaInfo(
                table_name="system_events",
                columns=[
                    ColumnInfo("timestamp", "timestamp"),
                    ColumnInfo("system_id", "string"),
                    ColumnInfo("event_type", "string"),
                    ColumnInfo("user_id", "string"),
                    ColumnInfo("severity", "string"),
                    ColumnInfo("description", "string")
                ]
            ),
            confidence_score=0.88,
            estimated_size_gb=0.9
        )
    ]
    
    return sources


def demonstrate_correlation_analysis():
    """Demonstrate cross-source correlation analysis."""
    
    print("=== Cross-Source Data Correlation Demonstration ===\n")
    
    # Create sample data
    sample_data = create_sample_security_data()
    data_sources = create_sample_data_sources()
    
    # Use firewall logs as primary data
    primary_results = sample_data['firewall_logs']
    
    print("1. Primary Data (Firewall Logs):")
    print(f"   - {primary_results.row_count} events")
    print(f"   - Time range: {primary_results.data[0]['timestamp']} to {primary_results.data[-1]['timestamp']}")
    print(f"   - Key IPs: {set(row['source_ip'] for row in primary_results.data)}")
    print()
    
    # Create correlator and context
    from unittest.mock import Mock
    mock_client = Mock()
    correlator = DataCorrelator(athena_client=mock_client)
    context = QueryContext(
        timeframe=TimeRange(
            start=datetime(2024, 1, 15, 10, 0, 0),
            end=datetime(2024, 1, 15, 10, 10, 0)
        ),
        priority_level="high"
    )
    
    # Simulate related data (normally would be queried from other sources)
    related_data = {
        'access_logs': sample_data['access_logs'],
        'system_events': sample_data['system_events']
    }
    
    print("2. Related Data Sources:")
    for source_name, data in related_data.items():
        print(f"   - {source_name}: {data.row_count} events")
    print()
    
    # Perform correlation analysis
    print("3. Performing Correlation Analysis...")
    correlated_data = correlator.correlate_data_across_sources(
        primary_results, data_sources[1:], context  # Use access and system sources as related
    )
    
    print(f"   - Overall correlation score: {correlated_data.correlation_score:.3f}")
    print(f"   - Correlation patterns found: {len(correlated_data.correlation_patterns)}")
    print()
    
    # Display correlation patterns
    print("4. Correlation Patterns Discovered:")
    for i, pattern in enumerate(correlated_data.correlation_patterns, 1):
        print(f"   Pattern {i}: {pattern.pattern_type}")
        print(f"   - Description: {pattern.description}")
        print(f"   - Confidence: {pattern.confidence:.3f}")
        if pattern.evidence:
            print(f"   - Evidence: {pattern.evidence[0]}")
        print()
    
    # Demonstrate time-series analysis
    print("5. Time-Series Trend Analysis:")
    
    # Add related data to correlated_data for timeline analysis
    correlated_data.related_data = related_data
    
    trends = correlator.analyze_time_series_trends(correlated_data, 'short_term')
    
    if trends:
        for i, trend in enumerate(trends, 1):
            print(f"   Trend {i}:")
            if 'anomaly_type' in trend:
                print(f"   - Type: {trend['anomaly_type']}")
                print(f"   - Severity: {trend.get('severity', 'unknown')}")
                print(f"   - Confidence: {trend.get('confidence', 0):.3f}")
            else:
                print(f"   - Type: {trend.get('trend_type', 'unknown')}")
                print(f"   - Events: {trend.get('total_events', 0)}")
            print()
    else:
        print("   - No significant trends detected in the time window")
        print()
    
    # Demonstrate timeline reconstruction
    print("6. Event Timeline Reconstruction:")
    timeline_events = correlated_data.get_timeline_events()
    
    print(f"   Total correlated events: {len(timeline_events)}")
    print("   Chronological sequence:")
    
    for event in timeline_events[:10]:  # Show first 10 events
        timestamp = event['timestamp']
        source = event['source']
        data = event['data']
        
        # Extract key information based on source
        if source == 'primary':
            info = f"Firewall: {data.get('action', 'N/A')} {data.get('source_ip', 'N/A')} -> {data.get('destination_ip', 'N/A')}:{data.get('port', 'N/A')}"
        elif 'access' in source:
            info = f"Access: {data.get('user_id', 'N/A')} {data.get('method', 'N/A')} {data.get('resource', 'N/A')} ({data.get('status_code', 'N/A')})"
        elif 'system' in source:
            info = f"System: {data.get('event_type', 'N/A')} - {data.get('description', 'N/A')}"
        else:
            info = f"Unknown source: {data}"
        
        print(f"   {timestamp} | {info}")
    
    print("\n=== Correlation Analysis Complete ===")


def demonstrate_attack_scenario_correlation():
    """Demonstrate correlation analysis for a simulated attack scenario."""
    
    print("\n=== Attack Scenario Correlation Analysis ===\n")
    
    # Create attack scenario data
    attack_time = datetime(2024, 1, 15, 14, 30, 0)
    
    # Attacker reconnaissance phase
    recon_data = QueryResults(
        query_id="recon_001",
        data=[
            {
                'timestamp': (attack_time - timedelta(minutes=10)).isoformat() + 'Z',
                'source_ip': '203.0.113.100',
                'destination_ip': '10.0.0.5',
                'action': 'DENY',
                'port': '22',
                'protocol': 'TCP'
            },
            {
                'timestamp': (attack_time - timedelta(minutes=8)).isoformat() + 'Z',
                'source_ip': '203.0.113.100',
                'destination_ip': '10.0.0.5',
                'action': 'DENY',
                'port': '80',
                'protocol': 'TCP'
            },
            {
                'timestamp': (attack_time - timedelta(minutes=5)).isoformat() + 'Z',
                'source_ip': '203.0.113.100',
                'destination_ip': '10.0.0.5',
                'action': 'ALLOW',
                'port': '443',
                'protocol': 'TCP'
            }
        ],
        column_names=['timestamp', 'source_ip', 'destination_ip', 'action', 'port', 'protocol'],
        row_count=3,
        data_scanned_gb=0.05,
        execution_time_ms=100,
        cost_usd=0.00025,
        query_sql="SELECT * FROM firewall_logs WHERE source_ip = '203.0.113.100'",
        source_tables=['firewall_logs']
    )
    
    # Attack execution phase
    attack_data = {
        'web_access': QueryResults(
            query_id="web_001",
            data=[
                {
                    'timestamp': attack_time.isoformat() + 'Z',
                    'source_ip': '203.0.113.100',
                    'resource': '/admin/login',
                    'method': 'POST',
                    'status_code': '401',
                    'user_agent': 'sqlmap/1.6.12'
                },
                {
                    'timestamp': (attack_time + timedelta(seconds=30)).isoformat() + 'Z',
                    'source_ip': '203.0.113.100',
                    'resource': '/admin/login',
                    'method': 'POST',
                    'status_code': '401',
                    'user_agent': 'sqlmap/1.6.12'
                },
                {
                    'timestamp': (attack_time + timedelta(minutes=2)).isoformat() + 'Z',
                    'source_ip': '203.0.113.100',
                    'resource': '/api/users?id=1\' OR 1=1--',
                    'method': 'GET',
                    'status_code': '500',
                    'user_agent': 'sqlmap/1.6.12'
                }
            ],
            column_names=['timestamp', 'source_ip', 'resource', 'method', 'status_code', 'user_agent'],
            row_count=3,
            data_scanned_gb=0.03,
            execution_time_ms=80,
            cost_usd=0.00015,
            query_sql="SELECT * FROM access_logs WHERE source_ip = '203.0.113.100'",
            source_tables=['access_logs']
        ),
        'security_alerts': QueryResults(
            query_id="alert_001",
            data=[
                {
                    'timestamp': (attack_time + timedelta(minutes=1)).isoformat() + 'Z',
                    'alert_type': 'BRUTE_FORCE_ATTACK',
                    'source_ip': '203.0.113.100',
                    'target_system': 'web-server-01',
                    'severity': 'HIGH',
                    'description': 'Multiple failed login attempts detected'
                },
                {
                    'timestamp': (attack_time + timedelta(minutes=3)).isoformat() + 'Z',
                    'alert_type': 'SQL_INJECTION_ATTEMPT',
                    'source_ip': '203.0.113.100',
                    'target_system': 'web-server-01',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection pattern detected in request'
                }
            ],
            column_names=['timestamp', 'alert_type', 'source_ip', 'target_system', 'severity', 'description'],
            row_count=2,
            data_scanned_gb=0.01,
            execution_time_ms=50,
            cost_usd=0.00005,
            query_sql="SELECT * FROM security_alerts WHERE source_ip = '203.0.113.100'",
            source_tables=['security_alerts']
        )
    }
    
    print("Attack Scenario: Multi-stage SQL Injection Attack")
    print(f"Attacker IP: 203.0.113.100")
    print(f"Target: web-server-01 (10.0.0.5)")
    print(f"Attack timeframe: {(attack_time - timedelta(minutes=10)).strftime('%H:%M:%S')} - {(attack_time + timedelta(minutes=5)).strftime('%H:%M:%S')}")
    print()
    
    # Perform correlation analysis
    from unittest.mock import Mock
    mock_client = Mock()
    correlator = DataCorrelator(athena_client=mock_client)
    context = QueryContext(
        timeframe=TimeRange(
            start=attack_time - timedelta(minutes=15),
            end=attack_time + timedelta(minutes=10)
        ),
        priority_level="critical"
    )
    
    correlated_attack_data = correlator.correlate_data_across_sources(
        recon_data, [], context
    )
    
    # Add attack data to correlation
    correlated_attack_data.related_data = attack_data
    
    # Analyze attack timeline
    print("Attack Timeline Analysis:")
    timeline = correlated_attack_data.get_timeline_events()
    
    phases = {
        'reconnaissance': [],
        'attack': [],
        'detection': []
    }
    
    for event in timeline:
        timestamp_str = event['timestamp']
        if timestamp_str.endswith('Z'):
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            timestamp = datetime.fromisoformat(timestamp_str)
        
        # Convert to naive datetime for comparison
        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)
        
        if timestamp < attack_time:
            phases['reconnaissance'].append(event)
        elif 'alert' in event['source']:
            phases['detection'].append(event)
        else:
            phases['attack'].append(event)
    
    for phase_name, events in phases.items():
        if events:
            print(f"\n{phase_name.title()} Phase ({len(events)} events):")
            for event in events:
                data = event['data']
                timestamp = event['timestamp']
                
                if phase_name == 'reconnaissance':
                    print(f"  {timestamp} | Port scan: {data.get('port')} ({data.get('action')})")
                elif phase_name == 'attack':
                    if 'resource' in data:
                        resource = data['resource'][:50] + '...' if len(data['resource']) > 50 else data['resource']
                        print(f"  {timestamp} | Web request: {data.get('method')} {resource} ({data.get('status_code')})")
                elif phase_name == 'detection':
                    print(f"  {timestamp} | Alert: {data.get('alert_type')} - {data.get('severity')}")
    
    # Calculate attack metrics
    print(f"\nAttack Metrics:")
    if timeline:
        start_time = datetime.fromisoformat(timeline[0]['timestamp'].replace('Z', '+00:00')).replace(tzinfo=None)
        end_time = datetime.fromisoformat(timeline[-1]['timestamp'].replace('Z', '+00:00')).replace(tzinfo=None)
        duration = end_time - start_time
        print(f"- Total attack duration: {duration}")
    else:
        print(f"- Total attack duration: Unknown")
    print(f"- Reconnaissance attempts: {len(phases['reconnaissance'])}")
    print(f"- Attack attempts: {len(phases['attack'])}")
    print(f"- Security alerts generated: {len(phases['detection'])}")
    print(f"- Overall correlation score: {correlated_attack_data.correlation_score:.3f}")
    
    print("\n=== Attack Scenario Analysis Complete ===")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_correlation_analysis()
    demonstrate_attack_scenario_correlation()