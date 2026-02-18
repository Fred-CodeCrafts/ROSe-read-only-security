"""
AWS Configuration and Client Management for AI Security Analyst

This module provides centralized configuration and client management for AWS services
including Bedrock, Athena, S3, and Glue with Free Tier optimization.
"""

import boto3
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class AWSConfig:
    """AWS configuration settings for AI Security Analyst"""
    
    # Project settings
    project_name: str = "ai-security-analyst"
    environment: str = "dev"
    region: str = "ap-southeast-2"  # User specified region
    
    # S3 settings
    security_data_bucket: str = "fred-codecrafts-security-data-lake"
    athena_results_bucket: str = "fred-codecrafts-athena-results"
    
    # Athena settings
    database_name: str = "security_analytic"  # User specified database name
    workgroup_name: Optional[str] = None
    query_timeout: int = 300  # 5 minutes
    max_query_cost: int = 1073741824  # 1GB for Free Tier
    
    # Bedrock settings
    default_model_id: str = "anthropic.claude-3-haiku-20240307-v1:0"  # Updated model
    max_tokens: int = 1000
    temperature: float = 0.1
    
    # IAM settings
    execution_role_arn: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values based on project settings"""
        if not self.security_data_bucket:
            account_id = self._get_account_id()
            self.security_data_bucket = f"{self.project_name}-security-data-lake-{self.environment}-{account_id}"
        
        if not self.athena_results_bucket:
            account_id = self._get_account_id()
            self.athena_results_bucket = f"{self.project_name}-athena-results-{self.environment}-{account_id}"
        
        if not self.database_name:
            self.database_name = f"{self.project_name}_security_catalog"
        
        if not self.workgroup_name:
            self.workgroup_name = f"{self.project_name}-workgroup-{self.environment}"
    
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            sts = boto3.client('sts', region_name=self.region)
            return sts.get_caller_identity()['Account']
        except Exception:
            return "unknown"
    
    @classmethod
    def from_environment(cls) -> 'AWSConfig':
        """Create configuration from environment variables"""
        return cls(
            project_name=os.getenv('PROJECT_NAME', 'ai-security-analyst'),
            environment=os.getenv('ENVIRONMENT', 'dev'),
            region=os.getenv('AWS_REGION', 'us-east-1'),
            security_data_bucket=os.getenv('SECURITY_DATA_BUCKET'),
            athena_results_bucket=os.getenv('ATHENA_RESULTS_BUCKET'),
            database_name=os.getenv('GLUE_DATABASE_NAME'),
            workgroup_name=os.getenv('ATHENA_WORKGROUP'),
            execution_role_arn=os.getenv('EXECUTION_ROLE_ARN')
        )


class AWSClientManager:
    """Manages AWS service clients with proper configuration and error handling"""
    
    def __init__(self, config: AWSConfig):
        self.config = config
        self._clients = {}
        self._session = None
    
    @property
    def session(self) -> boto3.Session:
        """Get or create boto3 session"""
        if not self._session:
            self._session = boto3.Session(region_name=self.config.region)
        return self._session
    
    def get_client(self, service_name: str) -> boto3.client:
        """Get AWS service client with caching"""
        if service_name not in self._clients:
            try:
                self._clients[service_name] = self.session.client(service_name)
                logger.info(f"✅ Created {service_name} client for region {self.config.region}")
            except Exception as e:
                logger.error(f"❌ Failed to create {service_name} client: {str(e)}")
                raise
        
        return self._clients[service_name]
    
    @property
    def bedrock_runtime(self) -> boto3.client:
        """Get Bedrock Runtime client"""
        return self.get_client('bedrock-runtime')
    
    @property
    def bedrock(self) -> boto3.client:
        """Get Bedrock client"""
        return self.get_client('bedrock')
    
    @property
    def athena(self) -> boto3.client:
        """Get Athena client"""
        return self.get_client('athena')
    
    @property
    def s3(self) -> boto3.client:
        """Get S3 client"""
        return self.get_client('s3')
    
    @property
    def glue(self) -> boto3.client:
        """Get Glue client"""
        return self.get_client('glue')
    
    @property
    def cloudwatch(self) -> boto3.client:
        """Get CloudWatch client"""
        return self.get_client('cloudwatch')
    
    def validate_permissions(self) -> Dict[str, bool]:
        """Validate that the current credentials have required permissions"""
        permissions = {}
        
        # Test Bedrock access
        try:
            self.bedrock.list_foundation_models()
            permissions['bedrock'] = True
            logger.info("✅ Bedrock permissions validated")
        except Exception as e:
            permissions['bedrock'] = False
            logger.warning(f"⚠️ Bedrock permissions issue: {str(e)}")
        
        # Test Athena access
        try:
            self.athena.list_work_groups()
            permissions['athena'] = True
            logger.info("✅ Athena permissions validated")
        except Exception as e:
            permissions['athena'] = False
            logger.warning(f"⚠️ Athena permissions issue: {str(e)}")
        
        # Test S3 access
        try:
            self.s3.list_buckets()
            permissions['s3'] = True
            logger.info("✅ S3 permissions validated")
        except Exception as e:
            permissions['s3'] = False
            logger.warning(f"⚠️ S3 permissions issue: {str(e)}")
        
        # Test Glue access
        try:
            self.glue.get_databases()
            permissions['glue'] = True
            logger.info("✅ Glue permissions validated")
        except Exception as e:
            permissions['glue'] = False
            logger.warning(f"⚠️ Glue permissions issue: {str(e)}")
        
        return permissions
    
    def get_available_bedrock_models(self) -> list:
        """Get list of available Bedrock foundation models"""
        try:
            response = self.bedrock.list_foundation_models()
            models = []
            
            for model in response.get('modelSummaries', []):
                models.append({
                    'modelId': model['modelId'],
                    'modelName': model['modelName'],
                    'providerName': model['providerName'],
                    'inputModalities': model.get('inputModalities', []),
                    'outputModalities': model.get('outputModalities', [])
                })
            
            logger.info(f"✅ Found {len(models)} available Bedrock models")
            return models
            
        except Exception as e:
            logger.error(f"❌ Failed to get Bedrock models: {str(e)}")
            return []
    
    def test_connectivity(self) -> bool:
        """Test connectivity to all required AWS services"""
        logger.info("🔍 Testing AWS service connectivity...")
        
        permissions = self.validate_permissions()
        required_services = ['bedrock', 'athena', 's3', 'glue']
        
        all_connected = all(permissions.get(service, False) for service in required_services)
        
        if all_connected:
            logger.info("✅ All AWS services are accessible")
        else:
            failed_services = [service for service in required_services 
                             if not permissions.get(service, False)]
            logger.error(f"❌ Failed to connect to services: {failed_services}")
        
        return all_connected


def create_aws_clients(config: Optional[AWSConfig] = None) -> AWSClientManager:
    """Factory function to create AWS client manager"""
    if config is None:
        config = AWSConfig.from_environment()
    
    return AWSClientManager(config)


def validate_aws_setup() -> bool:
    """Validate that AWS is properly configured for the AI Security Analyst"""
    try:
        config = AWSConfig.from_environment()
        client_manager = create_aws_clients(config)
        
        logger.info("🚀 Validating AWS setup for AI Security Analyst...")
        logger.info(f"Project: {config.project_name}")
        logger.info(f"Environment: {config.environment}")
        logger.info(f"Region: {config.region}")
        
        # Test connectivity
        if not client_manager.test_connectivity():
            return False
        
        # Get available models
        models = client_manager.get_available_bedrock_models()
        if not models:
            logger.warning("⚠️ No Bedrock models available - check region and permissions")
        
        logger.info("✅ AWS setup validation completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ AWS setup validation failed: {str(e)}")
        return False


if __name__ == "__main__":
    # Run validation when script is executed directly
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    if validate_aws_setup():
        sys.exit(0)
    else:
        sys.exit(1)