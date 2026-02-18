#!/usr/bin/env python3
"""
Flood Athena with realistic mock security data
"""

import boto3
import json
import random
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Initialize AWS clients
s3 = boto3.client('s3', region_name='ap-southeast-2')
athena = boto3.client('athena', region_name='ap-southeast-2')

# Configuration
BUCKET = 'fred-codecrafts-security-data-lake'
DATABASE = 'security_analytic'
WORKGROUP = 'ai-security-analyst-workgroup'

def generate_security_events(count=500):
    """Generate realistic security event data"""
    print(f"🔐 Generating {count} security events...")
    
    event_types = [
        'failed_login', 'successful_login', 'privilege_escalation',
        'suspicious_network', 'malware_detected', 'data_exfiltration',
        'sql_injection_attempt', 'xss_attempt', 'brute_force_attack',
        'unauthorized_access', 'port_scan', 'ddos_attempt'
    ]
    
    severity_map = {
        'failed_login': ['medium', 'high'],
        'successful_login': ['low', 'medium'],
        'privilege_escalation': ['critical', 'high'],
        'suspicious_network': ['high', 'critical'],
        'malware_detected': ['critical'],
        'data_exfiltration': ['critical'],
        'sql_injection_attempt': ['high', 'critical'],
        'xss_attempt': ['medium', 'high'],
        'brute_force_attack': ['high', 'critical'],
        'unauthorized_access': ['critical', 'high'],
        'port_scan': ['medium', 'high'],
        'ddos_attempt': ['critical']
    }
    
    usernames = [f'user{i}' for i in range(1, 51)] + [f'admin{i}' for i in range(1, 11)]
    
    events = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        event_type = random.choice(event_types)
        severity = random.choice(severity_map[event_type])
        
        event = {
            'timestamp': (base_time - timedelta(hours=random.randint(0, 168))).isoformat(),  # Last 7 days
            'event_type': event_type,
            'severity': severity,
            'source_ip': f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}',
            'username': random.choice(usernames),
            'destination_port': random.choice([22, 80, 443, 3389, 445, 1433, 3306, 5432]),
            'description': f'{event_type.replace("_", " ").title()} detected from suspicious source'
        }
        
        events.append(event)
    
    return events

def generate_threat_intelligence(count=200):
    """Generate threat intelligence data"""
    print(f"🎯 Generating {count} threat intelligence records...")
    
    threat_types = [
        'malware', 'ransomware', 'trojan', 'botnet', 'phishing',
        'apt', 'zero_day', 'vulnerability', 'exploit_kit'
    ]
    
    records = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        threat_type = random.choice(threat_types)
        
        record = {
            'timestamp': (base_time - timedelta(hours=random.randint(0, 168))).isoformat(),
            'threat_type': threat_type,
            'threat_name': f'{threat_type.upper()}-{random.randint(1000, 9999)}',
            'confidence_score': random.uniform(0.6, 1.0),
            'severity': random.choice(['low', 'medium', 'high', 'critical']),
            'source': random.choice(['internal_detection', 'threat_feed', 'honeypot', 'siem']),
            'indicators': json.dumps({
                'ip_addresses': [f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}' for _ in range(random.randint(1, 3))],
                'domains': [f'malicious{random.randint(1, 100)}.com'],
                'file_hashes': [f'sha256:{random.randint(10**63, 10**64-1):064x}']
            })
        }
        
        records.append(record)
    
    return records

def generate_user_activity(count=300):
    """Generate user activity logs"""
    print(f"👤 Generating {count} user activity records...")
    
    activities = [
        'file_access', 'file_modification', 'file_deletion',
        'login', 'logout', 'password_change', 'permission_change',
        'api_call', 'database_query', 'config_change'
    ]
    
    records = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        activity = random.choice(activities)
        
        record = {
            'timestamp': (base_time - timedelta(hours=random.randint(0, 168))).isoformat(),
            'user_id': f'user{random.randint(1, 100)}',
            'activity_type': activity,
            'resource': f'/path/to/resource/{random.randint(1, 1000)}',
            'source_ip': f'{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}',
            'user_agent': random.choice(['Mozilla/5.0', 'Chrome/90.0', 'Safari/14.0', 'API-Client/1.0']),
            'status': random.choice(['success', 'success', 'success', 'failed']),  # 75% success
            'risk_score': random.uniform(0, 100)
        }
        
        records.append(record)
    
    return records

def upload_to_s3(data, table_name, partition=''):
    """Upload data to S3 in JSON Lines format"""
    json_lines = '\n'.join([json.dumps(record) for record in data])
    
    key = f'{DATABASE}/{table_name}/{partition}data_{int(time.time())}.json'
    
    try:
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=json_lines.encode('utf-8'),
            ContentType='application/json'
        )
        return key
    except Exception as e:
        print(f"  ❌ Error uploading to S3: {e}")
        return None

def create_table_if_not_exists(table_name, schema):
    """Create Athena table if it doesn't exist"""
    create_query = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS {DATABASE}.{table_name} (
        {schema}
    )
    ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
    LOCATION 's3://{BUCKET}/{DATABASE}/{table_name}/'
    """
    
    try:
        response = athena.start_query_execution(
            QueryString=create_query,
            WorkGroup=WORKGROUP,
            ResultConfiguration={
                'OutputLocation': f's3://fred-codecrafts-athena-results/query-results/'
            }
        )
        
        query_id = response['QueryExecutionId']
        
        # Wait for completion
        for _ in range(30):
            status_response = athena.get_query_execution(QueryExecutionId=query_id)
            status = status_response['QueryExecution']['Status']['State']
            
            if status == 'SUCCEEDED':
                return True
            elif status in ['FAILED', 'CANCELLED']:
                return False
            time.sleep(1)
        
        return False
    except Exception as e:
        print(f"  ⚠️ Table creation note: {e}")
        return True  # Table might already exist

def run_sample_query(query, description):
    """Run a sample query and display results"""
    print(f"\n  📊 {description}")
    print(f"  Query: {query[:80]}...")
    
    try:
        response = athena.start_query_execution(
            QueryString=query,
            WorkGroup=WORKGROUP,
            ResultConfiguration={
                'OutputLocation': f's3://fred-codecrafts-athena-results/query-results/'
            }
        )
        
        query_id = response['QueryExecutionId']
        
        # Wait for completion
        for _ in range(30):
            status_response = athena.get_query_execution(QueryExecutionId=query_id)
            status = status_response['QueryExecution']['Status']['State']
            
            if status == 'SUCCEEDED':
                # Get results
                results = athena.get_query_results(QueryExecutionId=query_id)
                rows = results['ResultSet']['Rows']
                
                if len(rows) > 1:
                    print(f"  ✅ Query succeeded - {len(rows)-1} rows returned")
                    return True
                else:
                    print(f"  ✅ Query succeeded - no data yet")
                    return True
            elif status in ['FAILED', 'CANCELLED']:
                reason = status_response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                print(f"  ❌ Query failed: {reason}")
                return False
            time.sleep(1)
        
        print(f"  ⚠️ Query timed out")
        return False
    except Exception as e:
        print(f"  ❌ Query error: {e}")
        return False

def main():
    print("=" * 70)
    print("🌊 FLOODING ATHENA WITH MOCK SECURITY DATA")
    print("=" * 70)
    print()
    
    # Generate data
    security_events = generate_security_events(500)
    threat_intel = generate_threat_intelligence(200)
    user_activity = generate_user_activity(300)
    
    print()
    print("📤 Uploading data to S3...")
    print()
    
    # Create tables
    print("  🗄️ Creating security_events table...")
    create_table_if_not_exists('security_events', """
        timestamp string,
        event_type string,
        severity string,
        source_ip string,
        username string,
        destination_port int,
        description string
    """)
    
    print("  🗄️ Creating threat_intelligence table...")
    create_table_if_not_exists('threat_intelligence', """
        timestamp string,
        threat_type string,
        threat_name string,
        confidence_score double,
        severity string,
        source string,
        indicators string
    """)
    
    print("  🗄️ Creating user_activity table...")
    create_table_if_not_exists('user_activity', """
        timestamp string,
        user_id string,
        activity_type string,
        resource string,
        source_ip string,
        user_agent string,
        status string,
        risk_score double
    """)
    
    print()
    
    # Upload data
    print("  📦 Uploading security events...")
    key1 = upload_to_s3(security_events, 'security_events')
    if key1:
        print(f"    ✅ Uploaded {len(security_events)} events to {key1}")
    
    print("  📦 Uploading threat intelligence...")
    key2 = upload_to_s3(threat_intel, 'threat_intelligence')
    if key2:
        print(f"    ✅ Uploaded {len(threat_intel)} records to {key2}")
    
    print("  📦 Uploading user activity...")
    key3 = upload_to_s3(user_activity, 'user_activity')
    if key3:
        print(f"    ✅ Uploaded {len(user_activity)} records to {key3}")
    
    print()
    print("⏳ Waiting for data to be available in Athena (5 seconds)...")
    time.sleep(5)
    
    print()
    print("🔍 Running sample queries to verify data...")
    
    # Sample queries
    run_sample_query(
        f"SELECT COUNT(*) as total_events FROM {DATABASE}.security_events",
        "Total security events"
    )
    
    run_sample_query(
        f"SELECT severity, COUNT(*) as count FROM {DATABASE}.security_events GROUP BY severity ORDER BY count DESC",
        "Events by severity"
    )
    
    run_sample_query(
        f"SELECT event_type, COUNT(*) as count FROM {DATABASE}.security_events WHERE severity='critical' GROUP BY event_type ORDER BY count DESC LIMIT 5",
        "Top 5 critical event types"
    )
    
    run_sample_query(
        f"SELECT threat_type, COUNT(*) as count FROM {DATABASE}.threat_intelligence GROUP BY threat_type ORDER BY count DESC",
        "Threats by type"
    )
    
    run_sample_query(
        f"SELECT activity_type, COUNT(*) as count FROM {DATABASE}.user_activity WHERE status='failed' GROUP BY activity_type ORDER BY count DESC LIMIT 5",
        "Top 5 failed activities"
    )
    
    print()
    print("=" * 70)
    print(f"✨ COMPLETE! Uploaded {len(security_events) + len(threat_intel) + len(user_activity)} total records")
    print(f"📊 Database: {DATABASE}")
    print(f"🪣 Bucket: {BUCKET}")
    print(f"🌍 Region: ap-southeast-2")
    print()
    print("View in AWS Console:")
    print(f"https://ap-southeast-2.console.aws.amazon.com/athena/home?region=ap-southeast-2#/query-editor")
    print()
    print("Sample queries to try:")
    print(f"  SELECT * FROM {DATABASE}.security_events WHERE severity='critical' LIMIT 10;")
    print(f"  SELECT event_type, COUNT(*) FROM {DATABASE}.security_events GROUP BY event_type;")
    print(f"  SELECT * FROM {DATABASE}.threat_intelligence WHERE confidence_score > 0.9;")
    print("=" * 70)

if __name__ == '__main__':
    main()
