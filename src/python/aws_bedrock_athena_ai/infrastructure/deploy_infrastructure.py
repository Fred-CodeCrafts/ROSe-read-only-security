#!/usr/bin/env python3
"""
AWS Infrastructure Deployment Script for AI Security Analyst

This script deploys the CloudFormation template to set up:
- S3 buckets for security data lake and Athena results
- Glue database and tables for security data catalog
- IAM roles and policies for Bedrock and Athena access
- Athena workgroup with cost controls
"""

import boto3
import json
import time
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class InfrastructureDeployer:
    """Handles deployment of AWS infrastructure for AI Security Analyst"""
    
    def __init__(self, project_name: str = "ai-security-analyst", environment: str = "dev"):
        self.project_name = project_name
        self.environment = environment
        self.stack_name = f"{project_name}-infrastructure-{environment}"
        
        # Initialize AWS clients
        self.cloudformation = boto3.client('cloudformation')
        self.s3 = boto3.client('s3')
        self.athena = boto3.client('athena')
        self.glue = boto3.client('glue')
        
        # Get current directory for template path
        self.template_path = Path(__file__).parent / "cloudformation_template.yaml"
    
    def validate_template(self) -> bool:
        """Validate the CloudFormation template"""
        try:
            with open(self.template_path, 'r') as template_file:
                template_body = template_file.read()
            
            response = self.cloudformation.validate_template(TemplateBody=template_body)
            logger.info("✅ CloudFormation template is valid")
            return True
            
        except Exception as e:
            logger.error(f"❌ Template validation failed: {str(e)}")
            return False
    
    def check_stack_exists(self) -> bool:
        """Check if the CloudFormation stack already exists"""
        try:
            response = self.cloudformation.describe_stacks(StackName=self.stack_name)
            return len(response['Stacks']) > 0
        except self.cloudformation.exceptions.ClientError:
            return False
    
    def deploy_stack(self) -> bool:
        """Deploy or update the CloudFormation stack"""
        try:
            with open(self.template_path, 'r') as template_file:
                template_body = template_file.read()
            
            parameters = [
                {
                    'ParameterKey': 'ProjectName',
                    'ParameterValue': self.project_name
                },
                {
                    'ParameterKey': 'Environment',
                    'ParameterValue': self.environment
                }
            ]
            
            stack_exists = self.check_stack_exists()
            
            if stack_exists:
                logger.info(f"📝 Updating existing stack: {self.stack_name}")
                response = self.cloudformation.update_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                operation = "UPDATE"
            else:
                logger.info(f"🚀 Creating new stack: {self.stack_name}")
                response = self.cloudformation.create_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    OnFailure='ROLLBACK'
                )
                operation = "CREATE"
            
            # Wait for stack operation to complete
            return self.wait_for_stack_operation(operation)
            
        except Exception as e:
            logger.error(f"❌ Stack deployment failed: {str(e)}")
            return False
    
    def wait_for_stack_operation(self, operation: str) -> bool:
        """Wait for CloudFormation stack operation to complete"""
        logger.info(f"⏳ Waiting for stack {operation.lower()} to complete...")
        
        success_statuses = [f"{operation}_COMPLETE"]
        failure_statuses = [f"{operation}_FAILED", f"{operation}_ROLLBACK_COMPLETE"]
        
        while True:
            try:
                response = self.cloudformation.describe_stacks(StackName=self.stack_name)
                stack_status = response['Stacks'][0]['StackStatus']
                
                if stack_status in success_statuses:
                    logger.info(f"✅ Stack {operation.lower()} completed successfully")
                    return True
                elif stack_status in failure_statuses:
                    logger.error(f"❌ Stack {operation.lower()} failed with status: {stack_status}")
                    return False
                else:
                    logger.info(f"⏳ Stack status: {stack_status}")
                    time.sleep(30)
                    
            except Exception as e:
                logger.error(f"❌ Error checking stack status: {str(e)}")
                return False
    
    def get_stack_outputs(self) -> Dict[str, str]:
        """Get CloudFormation stack outputs"""
        try:
            response = self.cloudformation.describe_stacks(StackName=self.stack_name)
            outputs = response['Stacks'][0].get('Outputs', [])
            
            output_dict = {}
            for output in outputs:
                output_dict[output['OutputKey']] = output['OutputValue']
            
            return output_dict
            
        except Exception as e:
            logger.error(f"❌ Error getting stack outputs: {str(e)}")
            return {}
    
    def verify_deployment(self) -> bool:
        """Verify that all resources were created successfully"""
        logger.info("🔍 Verifying deployment...")
        
        outputs = self.get_stack_outputs()
        if not outputs:
            logger.error("❌ No stack outputs found")
            return False
        
        # Verify S3 buckets
        try:
            data_lake_bucket = outputs.get('SecurityDataLakeBucket')
            results_bucket = outputs.get('AthenaResultsBucket')
            
            if data_lake_bucket:
                self.s3.head_bucket(Bucket=data_lake_bucket)
                logger.info(f"✅ Security data lake bucket verified: {data_lake_bucket}")
            
            if results_bucket:
                self.s3.head_bucket(Bucket=results_bucket)
                logger.info(f"✅ Athena results bucket verified: {results_bucket}")
                
        except Exception as e:
            logger.error(f"❌ S3 bucket verification failed: {str(e)}")
            return False
        
        # Verify Glue database
        try:
            database_name = outputs.get('SecurityDataCatalog')
            if database_name:
                self.glue.get_database(Name=database_name)
                logger.info(f"✅ Glue database verified: {database_name}")
                
        except Exception as e:
            logger.error(f"❌ Glue database verification failed: {str(e)}")
            return False
        
        # Verify Athena workgroup
        try:
            workgroup_name = outputs.get('AthenaWorkgroup')
            if workgroup_name:
                self.athena.get_work_group(WorkGroup=workgroup_name)
                logger.info(f"✅ Athena workgroup verified: {workgroup_name}")
                
        except Exception as e:
            logger.error(f"❌ Athena workgroup verification failed: {str(e)}")
            return False
        
        # Verify CloudWatch resources
        try:
            cloudwatch = boto3.client('cloudwatch')
            logs = boto3.client('logs')
            
            # Verify log group
            log_group = outputs.get('ApplicationLogGroup')
            if log_group:
                logs.describe_log_groups(logGroupNamePrefix=log_group)
                logger.info(f"✅ CloudWatch log group verified: {log_group}")
            
            # Verify SNS topic
            sns = boto3.client('sns')
            alerts_topic = outputs.get('AlertsTopic')
            if alerts_topic:
                sns.get_topic_attributes(TopicArn=alerts_topic)
                logger.info(f"✅ SNS alerts topic verified: {alerts_topic}")
                
        except Exception as e:
            logger.error(f"❌ CloudWatch/SNS verification failed: {str(e)}")
            return False
        
        # Verify Lambda monitoring function
        try:
            lambda_client = boto3.client('lambda')
            monitoring_function = outputs.get('MonitoringFunction')
            if monitoring_function:
                lambda_client.get_function(FunctionName=monitoring_function)
                logger.info(f"✅ Monitoring Lambda function verified: {monitoring_function}")
                
        except Exception as e:
            logger.error(f"❌ Lambda function verification failed: {str(e)}")
            return False
        
        logger.info("✅ All infrastructure components verified successfully!")
        return True
    
    def create_sample_data_structure(self) -> bool:
        """Create sample directory structure in S3 for security data"""
        try:
            outputs = self.get_stack_outputs()
            bucket_name = outputs.get('SecurityDataLakeBucket')
            
            if not bucket_name:
                logger.error("❌ Security data lake bucket not found in outputs")
                return False
            
            # Create directory structure with placeholder files
            directories = [
                'events/year=2024/month=01/day=01/',
                'events/year=2024/month=01/day=02/',
                'configs/system_type=firewall/',
                'configs/system_type=server/',
                'configs/system_type=network/',
                'raw_logs/application/',
                'raw_logs/system/',
                'raw_logs/security/'
            ]
            
            for directory in directories:
                key = f"{directory}.gitkeep"
                self.s3.put_object(
                    Bucket=bucket_name,
                    Key=key,
                    Body=b"# Placeholder file for directory structure\n"
                )
            
            logger.info(f"✅ Sample data structure created in bucket: {bucket_name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create sample data structure: {str(e)}")
            return False
    
    def setup_monitoring_alerts(self, email_address: Optional[str] = None) -> bool:
        """Set up monitoring alerts and subscriptions"""
        try:
            outputs = self.get_stack_outputs()
            alerts_topic = outputs.get('AlertsTopic')
            
            if not alerts_topic:
                logger.error("❌ Alerts topic not found in outputs")
                return False
            
            sns = boto3.client('sns')
            
            # Subscribe email if provided
            if email_address:
                try:
                    sns.subscribe(
                        TopicArn=alerts_topic,
                        Protocol='email',
                        Endpoint=email_address
                    )
                    logger.info(f"✅ Email subscription added to alerts topic: {email_address}")
                    logger.info("📧 Please check your email and confirm the subscription")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to add email subscription: {str(e)}")
            
            # Test the monitoring function
            lambda_client = boto3.client('lambda')
            monitoring_function = outputs.get('MonitoringFunction')
            
            if monitoring_function:
                try:
                    response = lambda_client.invoke(
                        FunctionName=monitoring_function,
                        InvocationType='RequestResponse'
                    )
                    logger.info("✅ Monitoring function test completed successfully")
                except Exception as e:
                    logger.warning(f"⚠️ Monitoring function test failed: {str(e)}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to setup monitoring alerts: {str(e)}")
            return False
    
    def generate_configuration_file(self) -> bool:
        """Generate configuration file for the application"""
        try:
            outputs = self.get_stack_outputs()
            
            config = {
                "aws": {
                    "region": boto3.Session().region_name or "us-east-1",
                    "security_data_bucket": outputs.get('SecurityDataLakeBucket'),
                    "athena_results_bucket": outputs.get('AthenaResultsBucket'),
                    "athena_workgroup": outputs.get('AthenaWorkgroup'),
                    "glue_database": outputs.get('SecurityDataCatalog'),
                    "execution_role_arn": outputs.get('AISecurityAnalystRole'),
                    "log_group": outputs.get('ApplicationLogGroup'),
                    "alerts_topic": outputs.get('AlertsTopic')
                },
                "monitoring": {
                    "dashboard_url": outputs.get('MonitoringDashboard'),
                    "monitoring_function": outputs.get('MonitoringFunction')
                },
                "application": {
                    "project_name": self.project_name,
                    "environment": self.environment,
                    "cost_limits": {
                        "max_query_cost_usd": 0.05,
                        "daily_budget_usd": 1.00,
                        "athena_data_scan_limit_gb": 10.0
                    }
                }
            }
            
            config_path = Path(__file__).parent.parent / "config" / f"aws_config_{self.environment}.json"
            config_path.parent.mkdir(exist_ok=True)
            
            with open(config_path, 'w') as config_file:
                json.dump(config, config_file, indent=2)
            
            logger.info(f"✅ Configuration file generated: {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to generate configuration file: {str(e)}")
            return False
    
    def print_deployment_summary(self):
        """Print deployment summary with resource information"""
        outputs = self.get_stack_outputs()
        
        print("\n" + "="*60)
        print("🎉 AI SECURITY ANALYST INFRASTRUCTURE DEPLOYED!")
        print("="*60)
        print(f"Stack Name: {self.stack_name}")
        print(f"Project: {self.project_name}")
        print(f"Environment: {self.environment}")
        print("\n📋 DEPLOYED RESOURCES:")
        
        for key, value in outputs.items():
            print(f"  • {key}: {value}")
        
        print("\n🚀 NEXT STEPS:")
        print("  1. Update your application configuration with the resource names above")
        print("  2. Upload security data to the data lake bucket")
        print("  3. Test Athena queries using the configured workgroup")
        print("  4. Start using AWS Bedrock for AI analysis")
        print("  5. Monitor your application using the CloudWatch dashboard")
        print("  6. Set up email alerts by subscribing to the SNS topic")
        print("\n📊 MONITORING:")
        dashboard_url = outputs.get('MonitoringDashboard')
        if dashboard_url:
            print(f"  • Dashboard: {dashboard_url}")
        print(f"  • Alerts Topic: {outputs.get('AlertsTopic', 'N/A')}")
        print("\n💡 TIP: All resources are configured for AWS Free Tier optimization!")
        print("="*60)


def main():
    """Main deployment function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Deploy AI Security Analyst Infrastructure')
    parser.add_argument('--project-name', default='ai-security-analyst', 
                       help='Project name prefix for resources')
    parser.add_argument('--environment', default='dev', choices=['dev', 'staging', 'prod'],
                       help='Environment name')
    parser.add_argument('--verify-only', action='store_true',
                       help='Only verify existing deployment')
    parser.add_argument('--email', type=str,
                       help='Email address for monitoring alerts')
    
    args = parser.parse_args()
    
    deployer = InfrastructureDeployer(args.project_name, args.environment)
    
    if args.verify_only:
        if deployer.verify_deployment():
            deployer.print_deployment_summary()
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Full deployment process
    logger.info("🚀 Starting AI Security Analyst infrastructure deployment...")
    
    # Step 1: Validate template
    if not deployer.validate_template():
        sys.exit(1)
    
    # Step 2: Deploy stack
    if not deployer.deploy_stack():
        sys.exit(1)
    
    # Step 3: Verify deployment
    if not deployer.verify_deployment():
        sys.exit(1)
    
    # Step 4: Create sample data structure
    if not deployer.create_sample_data_structure():
        logger.warning("⚠️ Failed to create sample data structure, but deployment succeeded")
    
    # Step 5: Setup monitoring alerts
    if not deployer.setup_monitoring_alerts(args.email):
        logger.warning("⚠️ Failed to setup monitoring alerts, but deployment succeeded")
    
    # Step 6: Generate configuration file
    if not deployer.generate_configuration_file():
        logger.warning("⚠️ Failed to generate configuration file, but deployment succeeded")
    
    # Step 7: Print summary
    deployer.print_deployment_summary()
    
    logger.info("🎉 Infrastructure deployment completed successfully!")


if __name__ == "__main__":
    main()