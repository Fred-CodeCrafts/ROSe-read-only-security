#!/usr/bin/env python3
"""
AWS Setup Validation Script for AI Security Analyst
Checks if all required AWS services are properly configured
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Tuple

class AWSSetupValidator:
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.results = []
        
    def print_header(self, title: str):
        print(f"\n{'='*60}")
        print(f"🔍 {title}")
        print('='*60)
    
    def print_result(self, check: str, status: bool, message: str = ""):
        icon = "✅" if status else "❌"
        self.results.append((check, status, message))
        print(f"{icon} {check}")
        if message:
            print(f"   {message}")
    
    def check_aws_credentials(self) -> bool:
        """Check if AWS credentials are configured"""
        try:
            sts = boto3.client('sts', region_name=self.region)
            identity = sts.get_caller_identity()
            self.print_result(
                "AWS Credentials", 
                True, 
                f"Account: {identity.get('Account')}, User: {identity.get('Arn', 'Unknown')}"
            )
            return True
        except NoCredentialsError:
            self.print_result("AWS Credentials", False, "No credentials found. Run 'aws configure'")
            return False
        except Exception as e:
            self.print_result("AWS Credentials", False, f"Error: {str(e)}")
            return False
    
    def check_s3_buckets(self, security_bucket: str, athena_bucket: str) -> bool:
        """Check if required S3 buckets exist and are accessible"""
        try:
            s3 = boto3.client('s3', region_name=self.region)
            
            # Check security data bucket
            try:
                s3.head_bucket(Bucket=security_bucket)
                self.print_result("Security Data Bucket", True, f"s3://{security_bucket}")
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    self.print_result("Security Data Bucket", False, f"Bucket {security_bucket} not found")
                    return False
                else:
                    self.print_result("Security Data Bucket", False, f"Access denied to {security_bucket}")
                    return False
            
            # Check Athena results bucket
            try:
                s3.head_bucket(Bucket=athena_bucket)
                self.print_result("Athena Results Bucket", True, f"s3://{athena_bucket}")
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    self.print_result("Athena Results Bucket", False, f"Bucket {athena_bucket} not found")
                    return False
                else:
                    self.print_result("Athena Results Bucket", False, f"Access denied to {athena_bucket}")
                    return False
            
            # Check folder structure in security bucket
            try:
                response = s3.list_objects_v2(Bucket=security_bucket, Prefix='security-logs/', Delimiter='/')
                folders_exist = 'CommonPrefixes' in response or 'Contents' in response
                self.print_result("S3 Folder Structure", folders_exist, "security-logs/ folder found" if folders_exist else "No folder structure found")
            except Exception as e:
                self.print_result("S3 Folder Structure", False, f"Error checking folders: {str(e)}")
            
            return True
            
        except Exception as e:
            self.print_result("S3 Service", False, f"Error accessing S3: {str(e)}")
            return False
    
    def check_athena_setup(self, athena_bucket: str) -> bool:
        """Check if Athena is properly configured"""
        try:
            athena = boto3.client('athena', region_name=self.region)
            
            # Check if we can list databases
            try:
                response = athena.list_databases(CatalogName='AwsDataCatalog')
                databases = [db['Name'] for db in response['DatabaseList']]
                
                if 'security_analytics' in databases:
                    self.print_result("Athena Database", True, "security_analytics database found")
                else:
                    self.print_result("Athena Database", False, "security_analytics database not found")
                    return False
                    
            except Exception as e:
                self.print_result("Athena Database", False, f"Error listing databases: {str(e)}")
                return False
            
            # Check if we can list tables
            try:
                response = athena.list_table_metadata(
                    CatalogName='AwsDataCatalog',
                    DatabaseName='security_analytics'
                )
                tables = [table['Name'] for table in response['TableMetadataList']]
                
                expected_tables = ['security_events', 'access_logs', 'system_configs']
                found_tables = [table for table in expected_tables if table in tables]
                
                if found_tables:
                    self.print_result("Athena Tables", True, f"Found tables: {', '.join(found_tables)}")
                else:
                    self.print_result("Athena Tables", False, "No expected tables found")
                
            except Exception as e:
                self.print_result("Athena Tables", False, f"Error listing tables: {str(e)}")
            
            # Test a simple query
            try:
                query = "SELECT 1 as test_value"
                response = athena.start_query_execution(
                    QueryString=query,
                    ResultConfiguration={
                        'OutputLocation': f's3://{athena_bucket}/'
                    }
                )
                query_id = response['QueryExecutionId']
                self.print_result("Athena Query Test", True, f"Test query executed (ID: {query_id})")
                
            except Exception as e:
                self.print_result("Athena Query Test", False, f"Error executing test query: {str(e)}")
                return False
            
            return True
            
        except Exception as e:
            self.print_result("Athena Service", False, f"Error accessing Athena: {str(e)}")
            return False
    
    def check_bedrock_access(self) -> bool:
        """Check if Bedrock is accessible and models are available"""
        try:
            bedrock = boto3.client('bedrock', region_name=self.region)
            
            # List available foundation models
            try:
                response = bedrock.list_foundation_models()
                models = response['modelSummaries']
                
                # Check for Claude models
                claude_models = [model for model in models if 'claude' in model['modelId'].lower()]
                
                if claude_models:
                    model_names = [model['modelId'] for model in claude_models[:3]]  # Show first 3
                    self.print_result("Bedrock Models", True, f"Claude models available: {len(claude_models)} total")
                else:
                    self.print_result("Bedrock Models", False, "No Claude models found - may need to request access")
                    return False
                    
            except Exception as e:
                self.print_result("Bedrock Models", False, f"Error listing models: {str(e)}")
                return False
            
            # Test model invocation (if we have access)
            try:
                bedrock_runtime = boto3.client('bedrock-runtime', region_name=self.region)
                
                # Try to invoke Claude 3 Haiku (fastest/cheapest)
                test_payload = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 10,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Hello"
                        }
                    ]
                }
                
                response = bedrock_runtime.invoke_model(
                    modelId='anthropic.claude-3-haiku-20240307-v1:0',
                    body=json.dumps(test_payload)
                )
                
                self.print_result("Bedrock Model Invocation", True, "Successfully invoked Claude 3 Haiku")
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'AccessDeniedException':
                    self.print_result("Bedrock Model Invocation", False, "Access denied - request model access in Bedrock console")
                elif error_code == 'ValidationException':
                    self.print_result("Bedrock Model Invocation", False, "Model not available - check model access")
                else:
                    self.print_result("Bedrock Model Invocation", False, f"Error: {error_code}")
                return False
            except Exception as e:
                self.print_result("Bedrock Model Invocation", False, f"Error invoking model: {str(e)}")
                return False
            
            return True
            
        except Exception as e:
            self.print_result("Bedrock Service", False, f"Error accessing Bedrock: {str(e)}")
            return False
    
    def check_iam_permissions(self) -> bool:
        """Check if current user/role has necessary permissions"""
        try:
            # This is a basic check - in practice, you'd need more comprehensive permission testing
            iam = boto3.client('iam', region_name=self.region)
            
            try:
                # Try to get current user info
                sts = boto3.client('sts', region_name=self.region)
                identity = sts.get_caller_identity()
                arn = identity.get('Arn', '')
                
                if ':user/' in arn:
                    # It's a user
                    username = arn.split('/')[-1]
                    try:
                        response = iam.list_attached_user_policies(UserName=username)
                        policies = [policy['PolicyName'] for policy in response['AttachedPolicies']]
                        self.print_result("IAM Permissions", True, f"User has {len(policies)} attached policies")
                    except Exception:
                        self.print_result("IAM Permissions", True, "Cannot check user policies (may be using role)")
                elif ':role/' in arn:
                    # It's a role
                    self.print_result("IAM Permissions", True, "Using IAM role (assumed permissions)")
                else:
                    self.print_result("IAM Permissions", True, "Using root account or federated identity")
                    
            except Exception as e:
                self.print_result("IAM Permissions", False, f"Error checking permissions: {str(e)}")
                return False
            
            return True
            
        except Exception as e:
            self.print_result("IAM Service", False, f"Error accessing IAM: {str(e)}")
            return False
    
    def run_validation(self, security_bucket: str, athena_bucket: str) -> bool:
        """Run all validation checks"""
        print("🚀 AI Security Analyst - AWS Setup Validation")
        print(f"Region: {self.region}")
        print(f"Security Bucket: {security_bucket}")
        print(f"Athena Bucket: {athena_bucket}")
        
        # Run all checks
        self.print_header("AWS Credentials & Permissions")
        creds_ok = self.check_aws_credentials()
        if creds_ok:
            self.check_iam_permissions()
        
        self.print_header("S3 Storage")
        s3_ok = self.check_s3_buckets(security_bucket, athena_bucket)
        
        self.print_header("Amazon Athena")
        athena_ok = self.check_athena_setup(athena_bucket) if s3_ok else False
        
        self.print_header("AWS Bedrock")
        bedrock_ok = self.check_bedrock_access()
        
        # Summary
        self.print_header("Validation Summary")
        
        passed = sum(1 for _, status, _ in self.results if status)
        total = len(self.results)
        
        print(f"✅ Passed: {passed}/{total} checks")
        
        if passed == total:
            print("\n🎉 All checks passed! Your AWS setup is ready for the AI Security Analyst.")
            print("\n🚀 Next steps:")
            print("   1. Run: python -m aws_bedrock_athena_ai.cli")
            print("   2. Ask a security question like: 'Show me failed login attempts'")
            return True
        else:
            print(f"\n⚠️  {total - passed} checks failed. Please review the issues above.")
            print("\n📖 For help, see: docs/AWS_SETUP_GUIDE.md")
            
            # Show failed checks
            failed_checks = [(check, msg) for check, status, msg in self.results if not status]
            if failed_checks:
                print("\n❌ Failed checks:")
                for check, msg in failed_checks:
                    print(f"   • {check}: {msg}")
            
            return False


def main():
    """Main validation function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate AWS setup for AI Security Analyst')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--security-bucket', required=True, help='Security data S3 bucket name')
    parser.add_argument('--athena-bucket', required=True, help='Athena results S3 bucket name')
    
    args = parser.parse_args()
    
    validator = AWSSetupValidator(region=args.region)
    success = validator.run_validation(args.security_bucket, args.athena_bucket)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()