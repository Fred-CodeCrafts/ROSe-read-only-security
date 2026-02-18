#!/usr/bin/env python3
"""
Flood CloudWatch with realistic mock security data
"""

import boto3
import random
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Initialize CloudWatch client
cloudwatch = boto3.client('cloudwatch', region_name='ap-southeast-2')

# Metric namespace
NAMESPACE = 'SecurityAnalytics'

def generate_security_events(count=100):
    """Generate realistic security event metrics"""
    print(f"📊 Generating {count} security event metrics...")
    
    event_types = [
        'LoginAttempt', 'FailedLogin', 'SuccessfulLogin',
        'APICall', 'DataAccess', 'FileModification',
        'NetworkConnection', 'PortScan', 'SQLInjectionAttempt',
        'XSSAttempt', 'BruteForceAttempt', 'UnauthorizedAccess'
    ]
    
    severity_levels = ['Low', 'Medium', 'High', 'Critical']
    
    metrics = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        event_type = random.choice(event_types)
        severity = random.choice(severity_levels)
        
        # Create realistic patterns
        if 'Failed' in event_type or 'Attempt' in event_type:
            value = random.randint(1, 50)
        elif severity == 'Critical':
            value = random.randint(1, 10)
        else:
            value = random.randint(1, 100)
        
        timestamp = base_time - timedelta(minutes=random.randint(0, 1440))  # Last 24 hours
        
        metrics.append({
            'MetricName': event_type,
            'Dimensions': [
                {'Name': 'Severity', 'Value': severity},
                {'Name': 'Environment', 'Value': 'Production'}
            ],
            'Timestamp': timestamp,
            'Value': value,
            'Unit': 'Count'
        })
    
    return metrics

def generate_threat_scores(count=50):
    """Generate threat score metrics"""
    print(f"🎯 Generating {count} threat score metrics...")
    
    metrics = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        timestamp = base_time - timedelta(minutes=random.randint(0, 1440))
        
        # Generate realistic threat scores (0-100)
        threat_score = random.triangular(0, 100, 30)  # Most scores around 30
        
        metrics.append({
            'MetricName': 'ThreatScore',
            'Dimensions': [
                {'Name': 'Source', 'Value': f'IP-{random.randint(1, 50)}'},
                {'Name': 'Environment', 'Value': 'Production'}
            ],
            'Timestamp': timestamp,
            'Value': threat_score,
            'Unit': 'None'
        })
    
    return metrics

def generate_response_times(count=100):
    """Generate API response time metrics"""
    print(f"⚡ Generating {count} response time metrics...")
    
    endpoints = [
        '/api/v1/security/question',
        '/api/v1/security/examples',
        '/api/v1/status',
        '/api/v1/auth/rate-limit'
    ]
    
    metrics = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        endpoint = random.choice(endpoints)
        timestamp = base_time - timedelta(minutes=random.randint(0, 1440))
        
        # Generate realistic response times (ms)
        response_time = random.lognormvariate(5, 0.5)  # Log-normal distribution
        
        metrics.append({
            'MetricName': 'ResponseTime',
            'Dimensions': [
                {'Name': 'Endpoint', 'Value': endpoint},
                {'Name': 'Environment', 'Value': 'Production'}
            ],
            'Timestamp': timestamp,
            'Value': response_time,
            'Unit': 'Milliseconds'
        })
    
    return metrics

def generate_user_activity(count=80):
    """Generate user activity metrics"""
    print(f"👥 Generating {count} user activity metrics...")
    
    activities = [
        'QuerySubmitted', 'ReportGenerated', 'DashboardViewed',
        'AlertTriggered', 'PolicyUpdated', 'UserLogin'
    ]
    
    metrics = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        activity = random.choice(activities)
        timestamp = base_time - timedelta(minutes=random.randint(0, 1440))
        
        value = random.randint(1, 20)
        
        metrics.append({
            'MetricName': activity,
            'Dimensions': [
                {'Name': 'UserType', 'Value': random.choice(['Admin', 'Analyst', 'Viewer'])},
                {'Name': 'Environment', 'Value': 'Production'}
            ],
            'Timestamp': timestamp,
            'Value': value,
            'Unit': 'Count'
        })
    
    return metrics

def generate_data_volume(count=60):
    """Generate data volume metrics"""
    print(f"💾 Generating {count} data volume metrics...")
    
    metrics = []
    base_time = datetime.utcnow()
    
    for i in range(count):
        timestamp = base_time - timedelta(minutes=random.randint(0, 1440))
        
        # Generate realistic data volumes (MB)
        volume = random.uniform(0.1, 500)
        
        metrics.append({
            'MetricName': 'DataProcessed',
            'Dimensions': [
                {'Name': 'DataType', 'Value': random.choice(['Logs', 'Events', 'Metrics'])},
                {'Name': 'Environment', 'Value': 'Production'}
            ],
            'Timestamp': timestamp,
            'Value': volume,
            'Unit': 'Megabytes'
        })
    
    return metrics

def send_metrics_batch(metrics, batch_size=20):
    """Send metrics to CloudWatch in batches"""
    total = len(metrics)
    sent = 0
    
    for i in range(0, total, batch_size):
        batch = metrics[i:i + batch_size]
        
        try:
            cloudwatch.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=batch
            )
            sent += len(batch)
            print(f"  ✅ Sent {sent}/{total} metrics")
            time.sleep(0.5)  # Rate limiting
        except Exception as e:
            print(f"  ❌ Error sending batch: {e}")
    
    return sent

def main():
    print("=" * 70)
    print("🌊 FLOODING CLOUDWATCH WITH MOCK DATA")
    print("=" * 70)
    print()
    
    total_sent = 0
    
    # Generate and send different types of metrics
    all_metrics = []
    
    all_metrics.extend(generate_security_events(150))
    all_metrics.extend(generate_threat_scores(80))
    all_metrics.extend(generate_response_times(120))
    all_metrics.extend(generate_user_activity(100))
    all_metrics.extend(generate_data_volume(80))
    
    print()
    print(f"📤 Sending {len(all_metrics)} total metrics to CloudWatch...")
    print()
    
    sent = send_metrics_batch(all_metrics)
    total_sent += sent
    
    print()
    print("=" * 70)
    print(f"✨ COMPLETE! Sent {total_sent} metrics to CloudWatch")
    print(f"📊 Namespace: {NAMESPACE}")
    print(f"🌍 Region: ap-southeast-2")
    print()
    print("View in AWS Console:")
    print("https://ap-southeast-2.console.aws.amazon.com/cloudwatch/home?region=ap-southeast-2#metricsV2:")
    print("=" * 70)

if __name__ == '__main__':
    main()
