#!/usr/bin/env python3
"""
Setup Athena workgroup and database for AI Security Analyst
"""

import boto3
import os
import sys
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

def setup_athena_resources():
    """Set up Athena workgroup and Glue database"""
    
    # Load environment configuration
    load_env_config()
    
    region = os.getenv('AWS_REGION', 'ap-southeast-2')
    athena_bucket = os.getenv('ATHENA_RESULTS_BUCKET', 'fred-codecrafts-athena-results')
    database_name = os.getenv('GLUE_DATABASE', 'security_analytic')
    
    print(f"🚀 Setting up Athena resources in {region}")
    print(f"📊 Database: {database_name}")
    print(f"🪣 Results bucket: {athena_bucket}")
    
    try:
        # Initialize AWS clients
        athena = boto3.client('athena', region_name=region)
        glue = boto3.client('glue', region_name=region)
        s3 = boto3.client('s3', region_name=region)
        
        # 1. Create S3 bucket for Athena results if it doesn't exist
        print("\n1. 📦 Setting up S3 bucket for Athena results...")
        try:
            s3.head_bucket(Bucket=athena_bucket)
            print(f"   ✅ Bucket {athena_bucket} already exists")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                try:
                    if region == 'us-east-1':
                        s3.create_bucket(Bucket=athena_bucket)
                    else:
                        s3.create_bucket(
                            Bucket=athena_bucket,
                            CreateBucketConfiguration={'LocationConstraint': region}
                        )
                    print(f"   ✅ Created bucket {athena_bucket}")
                except ClientError as create_error:
                    print(f"   ❌ Failed to create bucket: {create_error}")
                    return False
            else:
                print(f"   ❌ Error checking bucket: {e}")
                return False
        
        # 2. Create Glue database
        print(f"\n2. 🗄️ Setting up Glue database: {database_name}")
        try:
            glue.create_database(
                DatabaseInput={
                    'Name': database_name,
                    'Description': 'Security analytics database for AI Security Analyst'
                }
            )
            print(f"   ✅ Created database {database_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                print(f"   ✅ Database {database_name} already exists")
            else:
                print(f"   ❌ Failed to create database: {e}")
                return False
        
        # 3. Create or update Athena workgroup
        print("\n3. ⚙️ Setting up Athena workgroup...")
        workgroup_name = 'ai-security-analyst-workgroup'
        
        try:
            athena.create_work_group(
                Name=workgroup_name,
                Description='Workgroup for AI Security Analyst queries',
                Configuration={
                    'ResultConfiguration': {
                        'OutputLocation': f's3://{athena_bucket}/',
                        'EncryptionConfiguration': {
                            'EncryptionOption': 'SSE_S3'
                        }
                    },
                    'EnforceWorkGroupConfiguration': True,
                    'PublishCloudWatchMetricsEnabled': True,
                    'BytesScannedCutoffPerQuery': 1073741824,  # 1GB limit for cost control
                    'RequesterPaysEnabled': False
                }
            )
            print(f"   ✅ Created workgroup {workgroup_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRequestException' and 'already exists' in str(e):
                print(f"   ✅ Workgroup {workgroup_name} already exists")
            else:
                print(f"   ❌ Failed to create workgroup: {e}")
                return False
        
        # 4. Test Athena setup
        print("\n4. 🧪 Testing Athena setup...")
        try:
            response = athena.start_query_execution(
                QueryString='SHOW DATABASES',
                WorkGroup=workgroup_name,
                ResultConfiguration={
                    'OutputLocation': f's3://{athena_bucket}/'
                }
            )
            
            query_id = response['QueryExecutionId']
            print(f"   📊 Test query started: {query_id}")
            
            # Wait for query to complete
            import time
            for i in range(30):  # Wait up to 30 seconds
                status_response = athena.get_query_execution(QueryExecutionId=query_id)
                status = status_response['QueryExecution']['Status']['State']
                
                if status == 'SUCCEEDED':
                    print(f"   ✅ Test query completed successfully!")
                    break
                elif status == 'FAILED':
                    reason = status_response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
                    print(f"   ❌ Test query failed: {reason}")
                    return False
                elif status == 'CANCELLED':
                    print(f"   ⚠️ Test query was cancelled")
                    return False
                else:
                    print(f"   ⏳ Query status: {status} (waiting...)")
                    time.sleep(1)
            else:
                print(f"   ⚠️ Test query timed out")
                return False
                
        except ClientError as e:
            print(f"   ❌ Test query failed: {e}")
            return False
        
        print(f"\n🎉 Athena setup completed successfully!")
        print(f"\n📋 Configuration summary:")
        print(f"   • Region: {region}")
        print(f"   • Database: {database_name}")
        print(f"   • Workgroup: {workgroup_name}")
        print(f"   • Results bucket: s3://{athena_bucket}/")
        
        # Update .env file with workgroup
        print(f"\n💡 Add this to your .env file:")
        print(f"ATHENA_WORKGROUP={workgroup_name}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        return False

if __name__ == "__main__":
    success = setup_athena_resources()
    sys.exit(0 if success else 1)