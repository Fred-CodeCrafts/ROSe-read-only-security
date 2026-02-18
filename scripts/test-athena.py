#!/usr/bin/env python3
"""
Test Athena configuration with detailed error reporting
"""

import boto3
import os
import time
from botocore.exceptions import ClientError

def load_env_config():
    """Load configuration from .env file"""
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

def test_athena_detailed():
    """Test Athena with detailed error reporting"""
    
    load_env_config()
    
    region = os.getenv('AWS_REGION', 'ap-southeast-2')
    athena_bucket = os.getenv('ATHENA_RESULTS_BUCKET', 'fred-codecrafts-athena-results')
    workgroup = os.getenv('ATHENA_WORKGROUP', 'ai-security-analyst-workgroup')
    
    print(f"🧪 Testing Athena Configuration")
    print(f"Region: {region}")
    print(f"Results bucket: {athena_bucket}")
    print(f"Workgroup: {workgroup}")
    
    try:
        athena = boto3.client('athena', region_name=region)
        
        # Test 1: List workgroups
        print(f"\n1. 📋 Testing workgroup access...")
        try:
            workgroups = athena.list_work_groups()
            print(f"   ✅ Found {len(workgroups['WorkGroups'])} workgroups")
            
            # Check if our workgroup exists
            our_workgroup = None
            for wg in workgroups['WorkGroups']:
                if wg['Name'] == workgroup:
                    our_workgroup = wg
                    break
            
            if our_workgroup:
                print(f"   ✅ Workgroup '{workgroup}' found")
            else:
                print(f"   ⚠️ Workgroup '{workgroup}' not found")
                print(f"   Available workgroups: {[wg['Name'] for wg in workgroups['WorkGroups']]}")
                
        except ClientError as e:
            print(f"   ❌ Failed to list workgroups: {e}")
            return False
        
        # Test 2: Start a simple query
        print(f"\n2. 🔍 Testing query execution...")
        try:
            query = "SHOW DATABASES"
            
            # Try with workgroup if it exists
            if our_workgroup:
                response = athena.start_query_execution(
                    QueryString=query,
                    WorkGroup=workgroup
                )
            else:
                response = athena.start_query_execution(
                    QueryString=query,
                    ResultConfiguration={
                        'OutputLocation': f's3://{athena_bucket}/'
                    }
                )
            
            query_id = response['QueryExecutionId']
            print(f"   📊 Query started: {query_id}")
            
            # Wait for completion and get detailed status
            for i in range(30):
                status_response = athena.get_query_execution(QueryExecutionId=query_id)
                execution = status_response['QueryExecution']
                status = execution['Status']['State']
                
                print(f"   ⏳ Status: {status}")
                
                if status == 'SUCCEEDED':
                    print(f"   ✅ Query completed successfully!")
                    
                    # Get results
                    results = athena.get_query_results(QueryExecutionId=query_id)
                    print(f"   📊 Results: {len(results['ResultSet']['Rows'])} rows")
                    
                    return True
                    
                elif status == 'FAILED':
                    reason = execution['Status'].get('StateChangeReason', 'Unknown error')
                    print(f"   ❌ Query failed: {reason}")
                    
                    # Get more detailed error info
                    if 'AthenaError' in execution['Status']:
                        error_info = execution['Status']['AthenaError']
                        print(f"   🔍 Error details:")
                        print(f"      Category: {error_info.get('ErrorCategory', 'Unknown')}")
                        print(f"      Type: {error_info.get('ErrorType', 'Unknown')}")
                        print(f"      Message: {error_info.get('ErrorMessage', 'No message')}")
                    
                    return False
                    
                elif status == 'CANCELLED':
                    print(f"   ⚠️ Query was cancelled")
                    return False
                
                time.sleep(1)
            
            print(f"   ⚠️ Query timed out after 30 seconds")
            return False
            
        except ClientError as e:
            print(f"   ❌ Failed to execute query: {e}")
            return False
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_athena_detailed()
    if success:
        print(f"\n🎉 Athena is working correctly!")
    else:
        print(f"\n💡 Next steps:")
        print(f"   1. Check IAM permissions for Athena and S3")
        print(f"   2. Verify S3 bucket exists and is accessible")
        print(f"   3. Ensure workgroup configuration is correct")