"""
Error message templates for AWS-powered features.

This module provides clear, actionable error messages with setup instructions
for common AWS configuration issues.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ErrorTemplate:
    """Template for error messages with recovery instructions"""
    error_code: str
    title: str
    message: str
    setup_instructions: str
    documentation_link: Optional[str] = None


# AWS Bedrock Error Templates
BEDROCK_NOT_CONFIGURED = ErrorTemplate(
    error_code="BEDROCK_NOT_CONFIGURED",
    title="AWS Bedrock Not Configured",
    message=(
        "AWS Bedrock is not configured or accessible. "
        "The system is running in demo mode with simulated responses."
    ),
    setup_instructions="""
To enable AWS Bedrock:

1. Configure AWS credentials:
   aws configure
   
2. Ensure you have Bedrock access in your AWS account:
   - Go to AWS Console > Bedrock
   - Request model access for Claude or other models
   - Wait for approval (usually instant for Claude)

3. Set environment variables (optional):
   export AWS_REGION=us-east-1
   export BEDROCK_MODEL_ID=anthropic.claude-v2

4. Restart the application

For more details, see: docs/setup/aws-bedrock-setup.md
""",
    documentation_link="https://docs.aws.amazon.com/bedrock/latest/userguide/getting-started.html"
)

BEDROCK_ACCESS_DENIED = ErrorTemplate(
    error_code="BEDROCK_ACCESS_DENIED",
    title="AWS Bedrock Access Denied",
    message=(
        "Your AWS credentials don't have permission to access Bedrock. "
        "Running in demo mode."
    ),
    setup_instructions="""
To fix Bedrock access:

1. Check your IAM permissions include:
   - bedrock:InvokeModel
   - bedrock:ListFoundationModels

2. Attach the AmazonBedrockFullAccess policy to your IAM user/role:
   aws iam attach-user-policy \\
     --user-name YOUR_USERNAME \\
     --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess

3. Request model access in AWS Console:
   - Go to Bedrock > Model access
   - Request access for desired models
   - Wait for approval

4. Restart the application
""",
    documentation_link="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html"
)

BEDROCK_MODEL_NOT_FOUND = ErrorTemplate(
    error_code="BEDROCK_MODEL_NOT_FOUND",
    title="Bedrock Model Not Available",
    message=(
        "The requested Bedrock model is not available in your region or account. "
        "Using demo mode."
    ),
    setup_instructions="""
To fix model availability:

1. Check available models in your region:
   aws bedrock list-foundation-models --region us-east-1

2. Request access to the model:
   - Go to AWS Console > Bedrock > Model access
   - Select the model you need
   - Click "Request model access"

3. Update your model configuration:
   export BEDROCK_MODEL_ID=anthropic.claude-v2

4. Restart the application

Recommended models:
- anthropic.claude-v2 (general purpose)
- anthropic.claude-instant-v1 (faster, cheaper)
""",
    documentation_link="https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html"
)

# Athena Error Templates
ATHENA_NOT_CONFIGURED = ErrorTemplate(
    error_code="ATHENA_NOT_CONFIGURED",
    title="AWS Athena Not Configured",
    message=(
        "AWS Athena database or table is not configured. "
        "Security queries will use demo data."
    ),
    setup_instructions="""
To enable AWS Athena:

1. Run the setup script:
   python scripts/setup-athena.py

2. Or manually configure:
   - Create S3 bucket for Athena results
   - Create Glue database: security_events
   - Create table: security_logs
   - Upload sample data

3. Set environment variables:
   export ATHENA_DATABASE=security_events
   export ATHENA_TABLE=security_logs
   export ATHENA_OUTPUT_BUCKET=s3://your-athena-results/

4. Restart the application

For detailed setup, see: docs/setup/athena-setup.md
""",
    documentation_link="https://docs.aws.amazon.com/athena/latest/ug/getting-started.html"
)

ATHENA_QUERY_FAILED = ErrorTemplate(
    error_code="ATHENA_QUERY_FAILED",
    title="Athena Query Failed",
    message=(
        "Failed to execute Athena query. Check your database configuration and permissions."
    ),
    setup_instructions="""
To fix Athena query issues:

1. Verify database and table exist:
   aws athena list-databases --catalog-name AwsDataCatalog
   aws athena list-table-metadata --catalog-name AwsDataCatalog --database-name security_events

2. Check IAM permissions include:
   - athena:StartQueryExecution
   - athena:GetQueryExecution
   - athena:GetQueryResults
   - s3:GetObject
   - s3:PutObject (for results bucket)
   - glue:GetDatabase
   - glue:GetTable

3. Verify S3 output location is accessible:
   aws s3 ls s3://your-athena-results/

4. Test with a simple query:
   python scripts/test-athena.py
""",
    documentation_link="https://docs.aws.amazon.com/athena/latest/ug/troubleshooting-athena.html"
)

# Cost Explorer Error Templates
COST_EXPLORER_NOT_CONFIGURED = ErrorTemplate(
    error_code="COST_EXPLORER_NOT_CONFIGURED",
    title="AWS Cost Explorer Not Configured",
    message=(
        "AWS Cost Explorer is not enabled or accessible. "
        "Cost optimization features will show demo data."
    ),
    setup_instructions="""
To enable Cost Explorer:

1. Enable Cost Explorer in AWS Console:
   - Go to AWS Billing > Cost Explorer
   - Click "Enable Cost Explorer"
   - Wait 24 hours for data to populate

2. Ensure IAM permissions include:
   - ce:GetCostAndUsage
   - ce:GetCostForecast

3. Set environment variable (optional):
   export ENABLE_COST_TRACKING=true

4. Restart the application

Note: Cost Explorer has a 24-hour delay for data availability.
""",
    documentation_link="https://docs.aws.amazon.com/cost-management/latest/userguide/ce-enable.html"
)

# General AWS Error Templates
AWS_CREDENTIALS_NOT_FOUND = ErrorTemplate(
    error_code="AWS_CREDENTIALS_NOT_FOUND",
    title="AWS Credentials Not Found",
    message=(
        "No AWS credentials found. Running in demo mode. "
        "Configure credentials to use AWS services."
    ),
    setup_instructions="""
To configure AWS credentials:

1. Install AWS CLI:
   https://aws.amazon.com/cli/

2. Configure credentials:
   aws configure
   
   You'll need:
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region (e.g., us-east-1)
   - Output format (json)

3. Or set environment variables:
   export AWS_ACCESS_KEY_ID=your_key_id
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1

4. Or use IAM role (if running on EC2/ECS)

5. Verify credentials:
   aws sts get-caller-identity

6. Restart the application
""",
    documentation_link="https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html"
)

AWS_REGION_NOT_SUPPORTED = ErrorTemplate(
    error_code="AWS_REGION_NOT_SUPPORTED",
    title="AWS Region Not Supported",
    message=(
        "The configured AWS region doesn't support required services. "
        "Using demo mode."
    ),
    setup_instructions="""
To fix region issues:

1. Check service availability in your region:
   - Bedrock: us-east-1, us-west-2, eu-central-1
   - Athena: Available in most regions

2. Update your region:
   aws configure set region us-east-1

3. Or set environment variable:
   export AWS_REGION=us-east-1

4. Restart the application

Recommended regions for all features:
- us-east-1 (N. Virginia)
- us-west-2 (Oregon)
""",
    documentation_link="https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/"
)


def get_error_template(error_code: str) -> Optional[ErrorTemplate]:
    """Get error template by error code"""
    templates = {
        "BEDROCK_NOT_CONFIGURED": BEDROCK_NOT_CONFIGURED,
        "BEDROCK_ACCESS_DENIED": BEDROCK_ACCESS_DENIED,
        "BEDROCK_MODEL_NOT_FOUND": BEDROCK_MODEL_NOT_FOUND,
        "ATHENA_NOT_CONFIGURED": ATHENA_NOT_CONFIGURED,
        "ATHENA_QUERY_FAILED": ATHENA_QUERY_FAILED,
        "COST_EXPLORER_NOT_CONFIGURED": COST_EXPLORER_NOT_CONFIGURED,
        "AWS_CREDENTIALS_NOT_FOUND": AWS_CREDENTIALS_NOT_FOUND,
        "AWS_REGION_NOT_SUPPORTED": AWS_REGION_NOT_SUPPORTED,
    }
    return templates.get(error_code)


def format_error_message(template: ErrorTemplate, include_instructions: bool = True) -> str:
    """Format error template into a user-friendly message"""
    message = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ {template.title:^76} ║
╚══════════════════════════════════════════════════════════════════════════════╝

{template.message}
"""
    
    if include_instructions:
        message += f"\n{template.setup_instructions}"
    
    if template.documentation_link:
        message += f"\n📚 Documentation: {template.documentation_link}\n"
    
    return message


def format_error_response(error_code: str, include_instructions: bool = True) -> dict:
    """Format error as JSON response for API"""
    template = get_error_template(error_code)
    if not template:
        return {
            "error": "UNKNOWN_ERROR",
            "message": "An unknown error occurred",
            "instructions": "Please check the logs for more details"
        }
    
    response = {
        "error": template.error_code,
        "title": template.title,
        "message": template.message,
    }
    
    if include_instructions:
        response["setup_instructions"] = template.setup_instructions
        response["documentation_link"] = template.documentation_link
    
    return response
