#!/usr/bin/env python3
"""
Command Line Interface for AI Security Analyst

Provides basic CLI commands for setup, validation, and management.
"""

import argparse
import sys
import logging
from pathlib import Path

from aws_bedrock_athena_ai.config import validate_aws_setup, AWSConfig, create_aws_clients
from aws_bedrock_athena_ai.infrastructure import InfrastructureDeployer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_validate(args):
    """Validate AWS setup and configuration"""
    logger.info("🔍 Validating AWS setup for AI Security Analyst...")
    
    if validate_aws_setup():
        print("✅ AWS setup validation successful!")
        return 0
    else:
        print("❌ AWS setup validation failed!")
        return 1


def cmd_deploy(args):
    """Deploy AWS infrastructure"""
    logger.info("🚀 Deploying AWS infrastructure...")
    
    deployer = InfrastructureDeployer(args.project_name, args.environment)
    
    # Validate template
    if not deployer.validate_template():
        print("❌ CloudFormation template validation failed!")
        return 1
    
    # Deploy stack
    if not deployer.deploy_stack():
        print("❌ Infrastructure deployment failed!")
        return 1
    
    # Verify deployment
    if not deployer.verify_deployment():
        print("❌ Infrastructure verification failed!")
        return 1
    
    # Create sample data structure
    if not deployer.create_sample_data_structure():
        logger.warning("⚠️ Failed to create sample data structure")
    
    # Print summary
    deployer.print_deployment_summary()
    print("✅ Infrastructure deployment completed successfully!")
    return 0


def cmd_status(args):
    """Check status of deployed infrastructure"""
    logger.info("📊 Checking infrastructure status...")
    
    try:
        config = AWSConfig.from_environment()
        config.project_name = args.project_name
        config.environment = args.environment
        
        client_manager = create_aws_clients(config)
        
        # Test connectivity
        if client_manager.test_connectivity():
            print("✅ All AWS services are accessible")
        else:
            print("❌ Some AWS services are not accessible")
            return 1
        
        # Get available models
        models = client_manager.get_available_bedrock_models()
        print(f"📋 Available Bedrock models: {len(models)}")
        
        for model in models[:5]:  # Show first 5 models
            print(f"  • {model['modelId']} ({model['providerName']})")
        
        if len(models) > 5:
            print(f"  ... and {len(models) - 5} more models")
        
        return 0
        
    except Exception as e:
        logger.error(f"❌ Status check failed: {str(e)}")
        return 1


def cmd_info(args):
    """Display project information"""
    print("🤖 AI Security Analyst in Your Pocket")
    print("=" * 50)
    print("A breakthrough AI application that combines AWS Bedrock's")
    print("reasoning with Amazon Athena's data querying power.")
    print()
    print("📋 Project Information:")
    print(f"  • Version: 0.1.0")
    print(f"  • Python: {sys.version.split()[0]}")
    print(f"  • Project Path: {Path(__file__).parent}")
    print()
    print("🚀 Quick Commands:")
    print("  • Validate setup: ai-security-analyst validate")
    print("  • Deploy infrastructure: ai-security-analyst deploy")
    print("  • Check status: ai-security-analyst status")
    print()
    print("📚 Documentation: See README.md for detailed instructions")
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI Security Analyst - AWS Bedrock + Athena Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ai-security-analyst validate
  ai-security-analyst deploy --project-name my-security-ai
  ai-security-analyst status --environment prod
  ai-security-analyst info
        """
    )
    
    # Global arguments
    parser.add_argument('--project-name', default='ai-security-analyst',
                       help='Project name prefix for resources')
    parser.add_argument('--environment', default='dev', 
                       choices=['dev', 'staging', 'prod'],
                       help='Environment name')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', 
                                          help='Validate AWS setup and permissions')
    validate_parser.set_defaults(func=cmd_validate)
    
    # Deploy command
    deploy_parser = subparsers.add_parser('deploy',
                                        help='Deploy AWS infrastructure')
    deploy_parser.set_defaults(func=cmd_deploy)
    
    # Status command
    status_parser = subparsers.add_parser('status',
                                        help='Check infrastructure status')
    status_parser.set_defaults(func=cmd_status)
    
    # Info command
    info_parser = subparsers.add_parser('info',
                                      help='Display project information')
    info_parser.set_defaults(func=cmd_info)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Execute command
    if hasattr(args, 'func'):
        try:
            return args.func(args)
        except KeyboardInterrupt:
            print("\n⚠️ Operation cancelled by user")
            return 1
        except Exception as e:
            logger.error(f"❌ Command failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    else:
        # No command specified, show help
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())