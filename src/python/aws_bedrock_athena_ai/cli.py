#!/usr/bin/env python3
"""
Command Line Interface for AI Security Analyst

Provides basic CLI commands for setup, validation, and management.
Also provides interactive chat interface for security analysis.
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, will use system environment variables

from aws_bedrock_athena_ai.config import validate_aws_setup, AWSConfig, create_aws_clients
from aws_bedrock_athena_ai.infrastructure import InfrastructureDeployer
from aws_bedrock_athena_ai.api.error_messages import (
    get_error_template, format_error_message
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_chat(args=None):
    """Interactive chat interface for security analysis"""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     ROSe AI Security Analyst - Interactive Chat             ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    
    # Check AWS availability
    demo_mode = False
    try:
        from aws_bedrock_athena_ai.api.aws_detector import AWSAvailabilityDetector
        detector = AWSAvailabilityDetector()
        
        if not detector.is_bedrock_available():
            demo_mode = True
            print("⚠️  AWS Bedrock not configured - Running in DEMO MODE")
            print("💡 Demo mode provides simulated responses for testing")
            print()
            
            # Show setup instructions if verbose logging enabled
            if logger.level <= logging.DEBUG:
                template = get_error_template("BEDROCK_NOT_CONFIGURED")
                if template:
                    print(format_error_message(template, include_instructions=True))
    except Exception as e:
        demo_mode = True
        logger.debug(f"AWS detection failed: {e}")
        print("⚠️  AWS services not available - Running in DEMO MODE")
        print("💡 Demo mode provides simulated responses for testing")
        print()
        
        # Show helpful error message
        if "credentials" in str(e).lower():
            template = get_error_template("AWS_CREDENTIALS_NOT_FOUND")
            if template:
                print(f"\n{template.message}")
                print("\n💡 Quick setup: Run 'aws configure' to set up credentials")
        print()
    
    # Display mode and instructions
    if demo_mode:
        print("🤖 Demo Mode Active - Ask me about security!")
    else:
        print("🤖 Connected to AWS Bedrock - Ask me about your security data!")
    
    print()
    print("Commands:")
    print("  • Type your security question and press Enter")
    print("  • Type 'exit' or 'quit' to end the session")
    print("  • Type 'help' for example questions")
    print()
    
    # Initialize demo response generator if in demo mode
    demo_generator = None
    if demo_mode:
        try:
            from aws_bedrock_athena_ai.api.demo_responses import DemoResponseGenerator
            demo_generator = DemoResponseGenerator()
        except ImportError as e:
            print(f"❌ Error loading demo mode: {e}")
            return 1
    
    # Chat loop
    conversation_id = f"cli-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    while True:
        try:
            # Get user input
            user_input = input("\n💬 You: ").strip()
            
            if not user_input:
                continue
            
            # Handle commands
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("\n👋 Thanks for using ROSe AI Security Analyst!")
                break
            
            if user_input.lower() == 'help':
                print("\n📚 Example Questions:")
                print("  • What are our top security risks?")
                print("  • Show me recent failed login attempts")
                print("  • Are there any suspicious network connections?")
                print("  • What security events happened in the last 24 hours?")
                print("  • Analyze authentication failures")
                continue
            
            # Process question
            print("\n🤔 Analyzing...")
            
            if demo_mode:
                # Use demo response generator
                response = demo_generator.generate_security_response(
                    user_input,
                    conversation_id
                )
                
                # Response is a dictionary
                print(f"\n🤖 ROSe: {response['executive_summary']}")
                
                if response.get('technical_details'):
                    print(f"\n📊 Key Findings:")
                    details = response['technical_details']
                    if isinstance(details, dict):
                        for key, value in list(details.items())[:3]:  # Show first 3 items
                            print(f"  • {key}: {value}")
            else:
                # Use real AWS Bedrock with Converse API
                try:
                    # Import here to avoid dependency issues
                    import boto3
                    from aws_bedrock_athena_ai.code_analyzer import create_enhanced_prompt
                    
                    bedrock = boto3.client('bedrock-runtime')
                    
                    # Create enhanced prompt with code context
                    enhanced_prompt = create_enhanced_prompt(user_input)
                    
                    # Use Converse API for Claude 3 models
                    response = bedrock.converse(
                        modelId='anthropic.claude-3-haiku-20240307-v1:0',
                        messages=[
                            {
                                'role': 'user',
                                'content': [{'text': enhanced_prompt}]
                            }
                        ],
                        inferenceConfig={
                            'maxTokens': 2000,  # Increased for detailed analysis
                            'temperature': 0.7
                        }
                    )
                    
                    # Extract response text
                    answer = response['output']['message']['content'][0]['text']
                    
                    print(f"\n🤖 ROSe: {answer}")
                    
                except Exception as e:
                    logger.error(f"Error querying AWS Bedrock: {e}", exc_info=True)
                    
                    # Provide helpful error message based on error type
                    error_code = None
                    if "access denied" in str(e).lower() or "unauthorized" in str(e).lower():
                        error_code = "BEDROCK_ACCESS_DENIED"
                    elif "model" in str(e).lower() and "not found" in str(e).lower():
                        error_code = "BEDROCK_MODEL_NOT_FOUND"
                    elif "credentials" in str(e).lower():
                        error_code = "AWS_CREDENTIALS_NOT_FOUND"
                    else:
                        error_code = "BEDROCK_NOT_CONFIGURED"
                    
                    template = get_error_template(error_code)
                    if template:
                        print(f"\n❌ {template.title}")
                        print(f"💡 {template.message}")
                    else:
                        print(f"\n❌ Error querying AWS Bedrock: {e}")
                    
                    print("💡 Falling back to demo mode...")
                    
                    # Fallback to demo mode
                    if not demo_generator:
                        from aws_bedrock_athena_ai.api.demo_responses import DemoResponseGenerator
                        demo_generator = DemoResponseGenerator()
                    
                    response = demo_generator.generate_security_response(
                        user_input,
                        conversation_id
                    )
                    print(f"\n🤖 ROSe (Demo): {response['executive_summary']}")
        
        except KeyboardInterrupt:
            print("\n\n👋 Session interrupted. Goodbye!")
            break
        except Exception as e:
            logger.error(f"Error in chat loop: {e}", exc_info=True)
            print(f"\n❌ An error occurred: {e}")
            print("💡 Please try again or type 'exit' to quit")
            
            # Don't crash - log error and continue
            continue
    
    return 0


def cmd_validate(args):
    """Validate AWS setup and configuration"""
    logger.info("🔍 Validating AWS setup for AI Security Analyst...")
    
    try:
        if validate_aws_setup():
            print("✅ AWS setup validation successful!")
            return 0
        else:
            print("❌ AWS setup validation failed!")
            
            # Provide helpful setup instructions
            template = get_error_template("AWS_CREDENTIALS_NOT_FOUND")
            if template:
                print(f"\n{template.message}")
                print("\n💡 To fix this, run: aws configure")
            
            return 1
    except Exception as e:
        logger.error(f"Validation error: {e}", exc_info=True)
        print(f"❌ Validation failed: {e}")
        
        # Provide context-specific error message
        if "credentials" in str(e).lower():
            template = get_error_template("AWS_CREDENTIALS_NOT_FOUND")
            if template:
                print(f"\n{template.message}")
        
        return 1


def cmd_deploy(args):
    """Deploy AWS infrastructure"""
    logger.info("🚀 Deploying AWS infrastructure...")
    
    try:
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
        
    except Exception as e:
        logger.error(f"Deployment error: {e}", exc_info=True)
        print(f"❌ Deployment failed: {e}")
        
        # Provide helpful error messages
        if "credentials" in str(e).lower():
            template = get_error_template("AWS_CREDENTIALS_NOT_FOUND")
            if template:
                print(f"\n{template.message}")
        elif "access denied" in str(e).lower():
            print("\n💡 Check that your AWS credentials have CloudFormation permissions")
        
        return 1


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
    # If called without arguments, start chat interface
    if len(sys.argv) == 1:
        return cmd_chat()
    
    parser = argparse.ArgumentParser(
        description='AI Security Analyst - AWS Bedrock + Athena Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ai-security-analyst validate
  ai-security-analyst deploy --project-name my-security-ai
  ai-security-analyst status --environment prod
  ai-security-analyst info
  ai-security-analyst chat
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
    
    # Chat command
    chat_parser = subparsers.add_parser('chat',
                                       help='Interactive chat interface for security analysis')
    chat_parser.set_defaults(func=cmd_chat)
    
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
            logger.error(f"❌ Command failed: {str(e)}", exc_info=True)
            
            # Provide helpful error messages based on error type
            if "credentials" in str(e).lower():
                template = get_error_template("AWS_CREDENTIALS_NOT_FOUND")
                if template:
                    print(f"\n{template.message}")
            elif "bedrock" in str(e).lower():
                template = get_error_template("BEDROCK_NOT_CONFIGURED")
                if template:
                    print(f"\n{template.message}")
            elif "athena" in str(e).lower():
                template = get_error_template("ATHENA_NOT_CONFIGURED")
                if template:
                    print(f"\n{template.message}")
            
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