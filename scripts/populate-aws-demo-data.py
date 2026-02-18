#!/usr/bin/env python3
"""
Populate AWS CloudWatch and Athena with demo data for screenshots
"""

import boto3
import json
import os
import sys
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import random

def load_env_config():
    """Load configuration from .env file"""
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

def create_sample_security_events():
    """Generate sample security events"""
    events = []
    now = datetime.utcnow()
    
    # Failed login attempts
    for i in range(50):
        events.append({
            'timestamp': (now - timedelta(hours=random.randint(0, 24))).isoformat(),
            'event_type': 'failed_login',
            'severity': 'high' if i < 15 else 'medium',
            'source_ip': f'203.0.113.{random.randint(1, 255)}',
            'username': f'user{random.randint(1, 100)}',
            'description': 'Failed login attempt detected'
        })
    
    # Suspicious network activity
    for i in range(30):
        events.append({
            'timestamp': (now - timedelta(hours=random.randint(0, 24))).isoformat(),
            'event_type': 'suspicious_network',
            'severity': 'critical' if i < 5 else 'high',
            'source_ip': f'198.51.100.{random.randint(1, 255)}',
            'destination_port': random.choice([22, 3389, 445, 1433]),
            'description': 'Suspicious network traffic detected'
        })
    
    # Privilege escalations
    for i in range(10):
        events.append({
            'timestamp': (now - timedelta(hours=random.randint(0, 24))).isoformat(),
            'event_type': 'privilege_escalation',
            'severity': 'critical',
            'username': f'admin{random.randint(1, 10)}',
            'description': 'Unauthorized privilege escalation attempt'
        })
    
    return events

def upload_sample_data_to_s3(s3_client, bucket_name, database_name):
    """Upload sample security events to S3"""
    print("\n📤 Uploading sample security data to S3...")
    
    events = create_sample_security_events()
    
    # Create JSON Lines format for Athena
    json_lines = '\n'.join([json.dumps(event) for event in events])
    
    # Upload to S3
    key = f'{database_name}/security_events/events.json'
    try:
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=json_lines.encode('utf-8'),
            ContentType='application/json'
        )
        print(f"   ✅ Uploaded {len(events)} events to s3://{bucket_name}/{key}")
        return True
    except ClientError as e:
        print(f"   ❌ Failed to upload data: {e}")
        return False

def create_athena_table(athena_client, database_name, bucket_name, workgroup):
    """Create Athena table for security events"""
    print("\n🗄️ Creating Athena table...")
    
    create_table_query = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS {database_name}.security_events (
        timestamp string,
        event_type string,
        severity string,
        source_ip string,
        username string,
        destination_port int,
        description string
    )
    ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
    LOCATION 's3://{bucket_name}/{database_name}/security_events/'
    """
    
    try:
        response = athena_client.start_query_execution(
            QueryString=create_table_query,
            WorkGroup=workgroup,
            ResultConfiguration={
                'OutputLocation': f's3://{bucket_name}/query-results/'
            }
        )
        
        query_id = response['QueryExecutionId']
        print(f"   📊 Table creation query started: {query_id}")
        
        # Wait for query to complete
        import time
        for i in range(30):
            status_response = athena_client.get_query_execution(QueryExecutionId=query_id)
            status = status_response['QueryExecution']['Status']['State']
            
            if status == 'SUCCEEDED':
                print(f"   ✅ Table created successfully!")
                return True
            elif status in ['FAILED', 'CANCELLED']:
                reason = status_response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                print(f"   ❌ Table creation failed: {reason}")
                return False
            time.sleep(1)
        
        print(f"   ⚠️ Table creation timed out")
        return False
        
    except ClientError as e:
        print(f"   ❌ Failed to create table: {e}")
        return False

def publish_cloudwatch_metrics(cloudwatch_client):
    """Publish sample metrics to CloudWatch"""
    print("\n📊 Publishing CloudWatch metrics...")
    
    namespace = 'AISecurityAnalyst'
    now = datetime.utcnow()
    
    metrics = [
        {
            'MetricName': 'ThreatDetectionCount',
            'Value': random.randint(10, 50),
            'Unit': 'Count',
            'Timestamp': now
        },
        {
            'MetricName': 'FailedLoginAttempts',
            'Value': random.randint(20, 100),
            'Unit': 'Count',
            'Timestamp': now
        },
        {
            'MetricName': 'SecurityScore',
            'Value': random.uniform(70, 95),
            'Unit': 'Percent',
            'Timestamp': now
        },
        {
            'MetricName': 'AthenaQueriesExecuted',
            'Value': random.randint(5, 20),
            'Unit': 'Count',
            'Timestamp': now
        },
        {
            'MetricName': 'BedrockAPICallsCount',
            'Value': random.randint(10, 30),
            'Unit': 'Count',
            'Timestamp': now
        }
    ]
    
    try:
        for metric in metrics:
            cloudwatch_client.put_metric_data(
                Namespace=namespace,
                MetricData=[metric]
            )
            print(f"   ✅ Published metric: {metric['MetricName']} = {metric['Value']:.2f}")
        
        return True
    except ClientError as e:
        print(f"   ❌ Failed to publish metrics: {e}")
        return False

def create_cloudwatch_dashboard(cloudwatch_client):
    """Create CloudWatch dashboard"""
    print("\n📈 Creating CloudWatch dashboard...")
    
    dashboard_name = 'ROSe-AI-Security-Analyst'
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AISecurityAnalyst", "ThreatDetectionCount", {"stat": "Sum"}]
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": os.getenv('AWS_REGION', 'ap-southeast-2'),
                    "title": "Threat Detection Count",
                    "yAxis": {"left": {"min": 0}}
                }
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AISecurityAnalyst", "FailedLoginAttempts", {"stat": "Sum"}]
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": os.getenv('AWS_REGION', 'ap-southeast-2'),
                    "title": "Failed Login Attempts",
                    "yAxis": {"left": {"min": 0}}
                }
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AISecurityAnalyst", "SecurityScore", {"stat": "Average"}]
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": os.getenv('AWS_REGION', 'ap-southeast-2'),
                    "title": "Security Score",
                    "yAxis": {"left": {"min": 0, "max": 100}}
                }
            },
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AISecurityAnalyst", "AthenaQueriesExecuted", {"stat": "Sum"}],
                        [".", "BedrockAPICallsCount", {"stat": "Sum"}]
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": os.getenv('AWS_REGION', 'ap-southeast-2'),
                    "title": "AWS Service Usage",
                    "yAxis": {"left": {"min": 0}}
                }
            }
        ]
    }
    
    try:
        cloudwatch_client.put_dashboard(
            DashboardName=dashboard_name,
            DashboardBody=json.dumps(dashboard_body)
        )
        print(f"   ✅ Created dashboard: {dashboard_name}")
        print(f"   🔗 View at: https://console.aws.amazon.com/cloudwatch/home?region={os.getenv('AWS_REGION', 'ap-southeast-2')}#dashboards:name={dashboard_name}")
        return True
    except ClientError as e:
        print(f"   ❌ Failed to create dashboard: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Populating AWS with demo data for ROSe AI Security Analyst")
    print("=" * 70)
    
    # Load environment configuration
    load_env_config()
    
    region = os.getenv('AWS_REGION', 'ap-southeast-2')
    security_bucket = os.getenv('SECURITY_DATA_BUCKET', 'fred-codecrafts-security-data-lake')
    athena_bucket = os.getenv('ATHENA_RESULTS_BUCKET', 'fred-codecrafts-athena-results')
    database_name = os.getenv('GLUE_DATABASE', 'security_analytics')
    workgroup = os.getenv('ATHENA_WORKGROUP', 'ai-security-analyst-workgroup')
    
    print(f"\n📋 Configuration:")
    print(f"   Region: {region}")
    print(f"   Security bucket: {security_bucket}")
    print(f"   Athena bucket: {athena_bucket}")
    print(f"   Database: {database_name}")
    print(f"   Workgroup: {workgroup}")
    
    try:
        # Initialize AWS clients
        s3 = boto3.client('s3', region_name=region)
        athena = boto3.client('athena', region_name=region)
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        
        # Step 1: Upload sample data to S3
        if not upload_sample_data_to_s3(s3, security_bucket, database_name):
            print("\n❌ Failed to upload sample data")
            return False
        
        # Step 2: Create Athena table
        if not create_athena_table(athena, database_name, security_bucket, workgroup):
            print("\n❌ Failed to create Athena table")
            return False
        
        # Step 3: Publish CloudWatch metrics
        if not publish_cloudwatch_metrics(cloudwatch):
            print("\n❌ Failed to publish CloudWatch metrics")
            return False
        
        # Step 4: Create CloudWatch dashboard
        if not create_cloudwatch_dashboard(cloudwatch):
            print("\n❌ Failed to create CloudWatch dashboard")
            return False
        
        print("\n" + "=" * 70)
        print("🎉 Demo data population completed successfully!")
        print("\n📸 Ready for screenshots:")
        print(f"   1. CloudWatch Dashboard:")
        print(f"      https://console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=ROSe-AI-Security-Analyst")
        print(f"   2. Athena Query Editor:")
        print(f"      https://console.aws.amazon.com/athena/home?region={region}")
        print(f"      Try query: SELECT * FROM {database_name}.security_events WHERE severity='critical' LIMIT 10")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
