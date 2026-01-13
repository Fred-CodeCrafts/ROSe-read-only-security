#!/usr/bin/env python3
"""
Demo of the AI Security Analyst System
Shows how to use the configured AWS infrastructure
"""

import os
import sys
import boto3
import json
from datetime import datetime

# Set up environment variables
os.environ['AWS_REGION'] = 'ap-southeast-2'
os.environ['SECURITY_DATA_BUCKET'] = 'fred-codecrafts-security-data-lake'
os.environ['ATHENA_RESULTS_BUCKET'] = 'fred-codecrafts-athena-results'
os.environ['GLUE_DATABASE'] = 'security_analytic'
os.environ['AWS_BEARER_TOKEN_BEDROCK'] = 'ABSKQmVkcm9ja0FQSUtleS1sZmpyLWF0LTQ1OTQ3MDk5OTk0NzpwWGMzeFRGdFFDN05udElBU3lLakJuK3hmRVRiNHBsa0NQNjJCV1YxbnNOM1F2VWNSbTlKTkYvMWpUOD0='

def demo_bedrock_analysis():
    """Demonstrate AI-powered security analysis"""
    print("🧠 AI Security Analysis Demo")
    print("-" * 40)
    
    try:
        bedrock_runtime = boto3.client('bedrock-runtime', region_name='ap-southeast-2')
        
        # Sample security scenario
        security_scenario = """
        Security Event Analysis:
        - Multiple failed login attempts from IP 203.0.113.50
        - User: admin (5 failed attempts in 2 minutes)
        - Followed by successful login from different IP 192.168.1.100
        - Malware detected on system shortly after
        """
        
        prompt = f"""You are a cybersecurity expert. Analyze this security scenario and provide:
1. Risk assessment (High/Medium/Low)
2. Potential attack type
3. Recommended actions

Scenario: {security_scenario}

Provide a concise analysis:"""
        
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 300,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        response = bedrock_runtime.invoke_model(
            modelId='anthropic.claude-3-haiku-20240307-v1:0',
            body=json.dumps(payload)
        )
        
        result = json.loads(response['body'].read())
        ai_analysis = result['content'][0]['text']
        
        print("🔍 AI Analysis:")
        print(ai_analysis)
        print("\n✅ Bedrock AI analysis completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Bedrock analysis failed: {str(e)}")
        return False

def demo_athena_query():
    """Demonstrate Athena database querying"""
    print("\n🗄️ Athena Database Demo")
    print("-" * 40)
    
    try:
        athena = boto3.client('athena', region_name='ap-southeast-2')
        
        # Simple test query
        query = "SHOW DATABASES"
        
        response = athena.start_query_execution(
            QueryString=query,
            ResultConfiguration={
                'OutputLocation': 's3://fred-codecrafts-athena-results/'
            }
        )
        
        query_id = response['QueryExecutionId']
        print(f"📊 Query executed: {query_id}")
        
        # Check query status
        import time
        time.sleep(2)  # Wait a moment
        
        status_response = athena.get_query_execution(QueryExecutionId=query_id)
        status = status_response['QueryExecution']['Status']['State']
        
        print(f"📈 Query status: {status}")
        
        if status == 'SUCCEEDED':
            print("✅ Athena query completed successfully!")
            return True
        else:
            print(f"⚠️ Query status: {status}")
            return False
            
    except Exception as e:
        print(f"❌ Athena query failed: {str(e)}")
        return False

def demo_s3_access():
    """Demonstrate S3 bucket access"""
    print("\n📦 S3 Storage Demo")
    print("-" * 40)
    
    try:
        s3 = boto3.client('s3', region_name='ap-southeast-2')
        
        # List bucket contents
        response = s3.list_objects_v2(
            Bucket='fred-codecrafts-security-data-lake',
            Prefix='security-logs/',
            Delimiter='/'
        )
        
        print("📁 Security data bucket structure:")
        if 'CommonPrefixes' in response:
            for prefix in response['CommonPrefixes']:
                print(f"   📂 {prefix['Prefix']}")
        
        if 'Contents' in response:
            for obj in response['Contents']:
                print(f"   📄 {obj['Key']} ({obj['Size']} bytes)")
        
        print("✅ S3 bucket access successful!")
        return True
        
    except Exception as e:
        print(f"❌ S3 access failed: {str(e)}")
        return False

def main():
    """Run the complete demo"""
    print("🚀 AI Security Analyst - Complete System Demo")
    print("=" * 60)
    print(f"🕒 Demo started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌏 AWS Region: {os.environ.get('AWS_REGION')}")
    print(f"🪣 Security Bucket: {os.environ.get('SECURITY_DATA_BUCKET')}")
    print(f"🗄️ Database: {os.environ.get('GLUE_DATABASE')}")
    
    # Run all demos
    results = []
    results.append(demo_s3_access())
    results.append(demo_athena_query())
    results.append(demo_bedrock_analysis())
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Demo Results Summary:")
    
    components = ["S3 Storage", "Athena Database", "Bedrock AI"]
    for i, (component, result) in enumerate(zip(components, results)):
        status = "✅ WORKING" if result else "❌ NEEDS ATTENTION"
        print(f"   {component}: {status}")
    
    success_rate = sum(results) / len(results) * 100
    print(f"\n🎯 Overall System Health: {success_rate:.0f}%")
    
    if success_rate >= 100:
        print("\n🎉 CONGRATULATIONS! Your AI Security Analyst is fully operational!")
        print("\n📋 Ready for:")
        print("   • Real-time security monitoring")
        print("   • Threat analysis and detection")
        print("   • Natural language security queries")
        print("   • Automated incident response")
        
        print("\n🚀 Try asking questions like:")
        print("   'What security events happened today?'")
        print("   'Show me suspicious login attempts'")
        print("   'Analyze potential threats'")
        
    else:
        print(f"\n⚠️ System is {success_rate:.0f}% operational")
        print("Some components may need additional configuration.")
    
    print(f"\n🕒 Demo completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()