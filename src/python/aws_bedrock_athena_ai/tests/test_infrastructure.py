"""
Tests for infrastructure deployment and configuration
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_aws

from aws_bedrock_athena_ai.config import AWSConfig, AWSClientManager
from aws_bedrock_athena_ai.infrastructure import InfrastructureDeployer


class TestAWSConfig:
    """Test AWS configuration management"""
    
    def test_aws_config_defaults(self):
        """Test default configuration values"""
        config = AWSConfig()
        
        assert config.project_name == "ai-security-analyst"
        assert config.environment == "dev"
        assert config.region == "us-east-1"
        assert config.default_model_id == "anthropic.claude-instant-v1"
        assert config.max_tokens == 1000
        assert config.temperature == 0.1
    
    def test_aws_config_from_environment(self):
        """Test configuration from environment variables"""
        with patch.dict('os.environ', {
            'PROJECT_NAME': 'test-project',
            'ENVIRONMENT': 'staging',
            'AWS_REGION': 'us-west-2'
        }):
            config = AWSConfig.from_environment()
            
            assert config.project_name == 'test-project'
            assert config.environment == 'staging'
            assert config.region == 'us-west-2'
    
    def test_bucket_name_generation(self):
        """Test automatic bucket name generation"""
        with patch.object(AWSConfig, '_get_account_id', return_value='123456789012'):
            config = AWSConfig(project_name='test', environment='dev')
            
            expected_data_bucket = 'test-security-data-lake-dev-123456789012'
            expected_results_bucket = 'test-athena-results-dev-123456789012'
            
            assert config.security_data_bucket == expected_data_bucket
            assert config.athena_results_bucket == expected_results_bucket


class TestAWSClientManager:
    """Test AWS client management"""
    
    def test_client_creation(self):
        """Test AWS client creation and caching"""
        config = AWSConfig()
        manager = AWSClientManager(config)
        
        with patch('boto3.Session') as mock_session:
            mock_client = Mock()
            mock_session.return_value.client.return_value = mock_client
            
            # First call should create client
            client1 = manager.get_client('s3')
            assert client1 == mock_client
            
            # Second call should return cached client
            client2 = manager.get_client('s3')
            assert client2 == mock_client
            
            # Should only create session once
            mock_session.assert_called_once_with(region_name=config.region)
    
    @mock_aws
    def test_s3_client_property(self):
        """Test S3 client property"""
        config = AWSConfig()
        manager = AWSClientManager(config)
        
        s3_client = manager.s3
        assert s3_client is not None
        
        # Test that it's cached
        s3_client2 = manager.s3
        assert s3_client is s3_client2


@mock_aws
class TestInfrastructureDeployer:
    """Test infrastructure deployment"""
    
    def test_deployer_initialization(self):
        """Test deployer initialization"""
        with patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-1'}):
            deployer = InfrastructureDeployer("test-project", "dev")
            
            assert deployer.project_name == "test-project"
            assert deployer.environment == "dev"
            assert deployer.stack_name == "test-project-infrastructure-dev"
    
    def test_template_validation(self):
        """Test CloudFormation template validation"""
        with patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-1'}):
            deployer = InfrastructureDeployer()
            
            # Mock the template file
            with patch('builtins.open', create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = """
                AWSTemplateFormatVersion: '2010-09-09'
                Resources:
                  TestResource:
                    Type: AWS::S3::Bucket
                """
                
                with patch.object(deployer.cloudformation, 'validate_template') as mock_validate:
                    mock_validate.return_value = {'Parameters': []}
                    
                    result = deployer.validate_template()
                    assert result is True
                    mock_validate.assert_called_once()
    
    def test_stack_exists_check(self):
        """Test stack existence check"""
        with patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-1'}):
            deployer = InfrastructureDeployer()
            
            # Test when stack doesn't exist
            with patch.object(deployer.cloudformation, 'describe_stacks') as mock_describe:
                from botocore.exceptions import ClientError
                mock_describe.side_effect = ClientError(
                    {'Error': {'Code': 'ValidationError'}}, 'DescribeStacks'
                )
                
                result = deployer.check_stack_exists()
                assert result is False
            
            # Test when stack exists
            with patch.object(deployer.cloudformation, 'describe_stacks') as mock_describe:
                mock_describe.return_value = {'Stacks': [{'StackName': 'test-stack'}]}
                
                result = deployer.check_stack_exists()
                assert result is True


class TestIntegration:
    """Integration tests for infrastructure components"""
    
    @mock_aws
    def test_end_to_end_setup(self):
        """Test end-to-end infrastructure setup"""
        config = AWSConfig(project_name='test', environment='test')
        manager = AWSClientManager(config)
        
        # Test that all required clients can be created
        clients = {
            's3': manager.s3,
            'glue': manager.glue,
            'athena': manager.athena,
        }
        
        for service, client in clients.items():
            assert client is not None, f"Failed to create {service} client"
    
    def test_permission_validation_structure(self):
        """Test permission validation returns proper structure"""
        config = AWSConfig()
        manager = AWSClientManager(config)
        
        # Mock the client methods directly instead of properties
        with patch.object(manager, 'get_client') as mock_get_client:
            mock_bedrock = Mock()
            mock_athena = Mock()
            mock_s3 = Mock()
            mock_glue = Mock()
            
            # Configure the mock to return different clients based on service name
            def get_client_side_effect(service_name):
                if service_name == 'bedrock':
                    return mock_bedrock
                elif service_name == 'athena':
                    return mock_athena
                elif service_name == 's3':
                    return mock_s3
                elif service_name == 'glue':
                    return mock_glue
                else:
                    return Mock()
            
            mock_get_client.side_effect = get_client_side_effect
            
            # Mock successful calls
            mock_bedrock.list_foundation_models.return_value = {}
            mock_athena.list_work_groups.return_value = {}
            mock_s3.list_buckets.return_value = {}
            mock_glue.get_databases.return_value = {}
            
            permissions = manager.validate_permissions()
            
            expected_services = ['bedrock', 'athena', 's3', 'glue']
            for service in expected_services:
                assert service in permissions
                assert isinstance(permissions[service], bool)