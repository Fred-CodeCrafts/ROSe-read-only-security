# ROSe AI Security Analyst Setup Guide

## Overview

This guide helps you set up **ROSe AI Security Analyst** - an AWS-powered cybersecurity analysis platform that combines Amazon Bedrock's AI reasoning with Amazon Athena's data querying capabilities to provide expert-level security insights.

## 🎯 Quick Start (15-30 minutes)

### Prerequisites

- **AWS Account** with administrative access
- **Python 3.8+** with pip
- **AWS CLI** installed and configured
- **Git** (for repository management)

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd rose-ai-security-analyst

# Setup Git hooks for security
./scripts/setup-git-hooks.ps1
```

### 2. AWS Infrastructure Setup

#### Option A: Automated Setup (Recommended)
```powershell
# Windows
.\scripts\aws-setup.ps1 -BucketPrefix "your-company" -Region "us-east-1"

# Linux/macOS
./scripts/aws-setup.sh --bucket-prefix "your-company" --region "us-east-1"
```

#### Option B: Manual Setup
Follow the detailed guide: [AWS Setup Guide](../AWS_SETUP_GUIDE.md)

### 3. Enable Amazon Bedrock Models

1. Go to [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
2. Click "Model catalog" → Find "Claude 3 Haiku"
3. Click "Open in Playground" to automatically enable the model
4. If prompted, provide use case: "Security data analysis and threat detection"

### 4. Deploy Infrastructure

```bash
# Install Python dependencies
pip install -r requirements.txt

# Deploy AWS infrastructure
python src/python/aws_bedrock_athena_ai/infrastructure/deploy_infrastructure.py

# Validate setup
python scripts/validate-aws-setup.py
```

### 5. Start Analyzing

```bash
# Launch the ROSe AI Security Analyst
python -m src.python.aws_bedrock_athena_ai.cli

# Or run the demo
python demo_ai_analyst.py
```

## 🏗️ Architecture Overview

### AWS-Native Design

ROSe AI Security Analyst leverages **AWS managed services** for enterprise-grade security analysis:

```
┌─────────────────────────────────────────────────────────────┐
│               ROSe AI Security Analyst Platform            │
├─────────────────────────────────────────────────────────────┤
│  🧠 Amazon Bedrock         │  🔍 Amazon Athena            │
│  • Claude 3 Models         │  • Serverless SQL Analytics  │
│  • Expert AI Reasoning     │  • Cost-Optimized Queries    │
│  • Natural Language        │  • Cross-Source Correlation  │
├─────────────────────────────────────────────────────────────┤
│  📊 Amazon S3 Data Lake    │  📈 CloudWatch Monitoring    │
│  • Security Events & Logs  │  • Real-time Dashboards      │
│  • System Configurations   │  • Automated Alerting        │
│  • Compliance Data         │  • Cost & Usage Tracking     │
├─────────────────────────────────────────────────────────────┤
│  ⚡ AWS Lambda Functions   │  🔐 IAM Security Controls    │
│  • Event Processing        │  • Fine-grained Permissions  │
│  • Automated Monitoring    │  • Audit Trail Logging       │
│  • Cost Optimization       │  • Encryption at Rest        │
└─────────────────────────────────────────────────────────────┘
```

### Cost Structure

- **AWS Free Tier Optimized**: $0-10/month for typical usage
- **Pay-per-use**: Only pay for what you analyze
- **Cost Controls**: Built-in budget limits and monitoring
- **Transparent Pricing**: Real-time cost tracking and alerts

## 📋 Detailed Setup

### Step 1: AWS Account Preparation

#### Install AWS CLI

**Windows (PowerShell):**
```powershell
# Install AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.msi" -o "AWSCLIV2.msi"
msiexec /i AWSCLIV2.msi

# Install Python
winget install Python.Python.3.11

# Install Git
winget install Git.Git
```

**Linux (Ubuntu/Debian):**
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install Python
sudo apt update
sudo apt install python3 python3-pip

# Install Git
sudo apt install git
```

**macOS:**
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Install Python (if not already installed)
brew install python

# Install Git (if not already installed)
brew install git
```

#### Configure AWS Credentials

```bash
# Configure AWS CLI
aws configure

# Enter your:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Default output format: json

# Verify configuration
aws sts get-caller-identity
```

#### Verify Installation

```bash
aws --version              # Should be 2.0+
python --version           # Should be 3.8+
git --version             # Should be 2.30+
```

### Step 2: AWS Services Setup

#### Enable Amazon Bedrock Models

1. **Navigate to Bedrock Console**:
   - Go to [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
   - Select your preferred region (us-east-1 or us-west-2 recommended)

2. **Enable Claude Models**:
   - Click "Model catalog" in the left sidebar
   - Find "Claude 3 Haiku" and click on it
   - Click "Open in Playground" to automatically enable
   - If prompted, provide use case: "Security data analysis and threat detection"

3. **Test Model Access**:
   ```bash
   aws bedrock list-foundation-models --region us-east-1
   ```

#### Deploy AWS Infrastructure

```bash
# Install Python dependencies
pip install -r requirements.txt

# Deploy infrastructure using CloudFormation
python src/python/aws_bedrock_athena_ai/infrastructure/deploy_infrastructure.py \
  --project-name "your-security-analyst" \
  --environment "dev" \
  --email "your-email@example.com"

# Verify deployment
aws cloudformation describe-stacks --stack-name ai-security-analyst-infrastructure-dev
```

### Step 3: Data Setup

#### Create S3 Directory Structure

The deployment automatically creates the following structure:

```
security-data-lake-bucket/
├── events/
│   └── year=2024/month=01/day=01/
├── configs/
│   ├── system_type=firewall/
│   ├── system_type=server/
│   └── system_type=network/
└── raw_logs/
    ├── application/
    ├── system/
    └── security/
```

#### Upload Sample Data

```bash
# Generate and upload sample security data
python scripts/generate-synthetic-data.ps1

# Upload to S3
aws s3 sync data/synthetic/ s3://your-security-data-lake-bucket/events/year=2024/month=01/day=01/
```

#### Verify Athena Setup

```bash
# Test Athena query
aws athena start-query-execution \
  --query-string "SELECT COUNT(*) FROM security_events WHERE year='2024'" \
  --result-configuration OutputLocation=s3://your-athena-results-bucket/ \
  --work-group ai-security-analyst-workgroup-dev
```

## 🔧 Configuration

### AWS Configuration

The system automatically generates configuration files after deployment:

```json
{
  "aws": {
    "region": "us-east-1",
    "security_data_bucket": "ai-security-analyst-security-data-lake-dev-123456789",
    "athena_results_bucket": "ai-security-analyst-athena-results-dev-123456789",
    "athena_workgroup": "ai-security-analyst-workgroup-dev",
    "glue_database": "ai_security_analyst_security_catalog",
    "execution_role_arn": "arn:aws:iam::123456789:role/ai-security-analyst-execution-role-dev"
  },
  "bedrock": {
    "models": {
      "fast": "anthropic.claude-3-haiku-20240307-v1:0",
      "balanced": "anthropic.claude-3-5-sonnet-20241022-v2:0",
      "powerful": "anthropic.claude-3-opus-20240229-v1:0"
    }
  },
  "cost_limits": {
    "max_query_cost_usd": 0.05,
    "daily_budget_usd": 1.00,
    "athena_data_scan_limit_gb": 10.0
  }
}
```

### Environment Variables

Create `.env` file (never commit this):

```bash
# AWS Configuration
AWS_REGION=us-east-1
AWS_PROFILE=default

# Application Configuration
LOG_LEVEL=INFO
ENABLE_COST_OPTIMIZATION=true
ENABLE_PII_REDACTION=true

# Security Configuration
ENABLE_SECRET_DETECTION=true
SYNTHETIC_DATA_ONLY=true
```

### CloudWatch Monitoring

Access your monitoring dashboard at:
```
https://console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=ai-security-analyst-dashboard-{environment}
```

### Alert Configuration

The system automatically creates alerts for:
- High Athena costs (>10GB data scanned per hour)
- Application errors (>10 errors per 5 minutes)
- Storage growth (>5GB in S3 data lake)
- Bedrock usage approaching cost thresholds

## 🧪 Testing the Setup

### End-to-End Test

```bash
# Run comprehensive system test
python scripts/validate-aws-setup.py

# Expected output:
# ✅ AWS credentials configured
# ✅ Bedrock models accessible
# ✅ S3 buckets created and accessible
# ✅ Athena workgroup configured
# ✅ CloudWatch monitoring active
# ✅ ROSe AI Security Analyst ready
```

### Security Test

```bash
# Test secret detection
echo "password = 'super_secret_123'" > test_file.py
git add test_file.py
git commit -m "test"  # Should be blocked by pre-commit hook

# Test AI analysis
python -c "
from src.python.aws_bedrock_athena_ai.nlp.simple_interface import SimpleNLInterface
interface = SimpleNLInterface()
result = interface.ask_question('What is the current security status?')
print('✅ AI analysis working' if result else '❌ AI analysis failed')
"

# Test Athena queries
python -c "
from src.python.aws_bedrock_athena_ai.data_detective.smart_data_detective import SmartDataDetective
detective = SmartDataDetective()
result = detective.discover_data_sources()
print('✅ Athena integration working' if result else '❌ Athena integration failed')
"
```

### Cost Validation

```bash
# Check current AWS costs
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE

# Verify cost controls are active
python -c "
from src.python.aws_bedrock_athena_ai.cost_optimization.cost_optimizer import CostOptimizer
optimizer = CostOptimizer()
print('✅ Cost controls active' if optimizer.check_budget_status() else '❌ Cost controls inactive')
"
```

## 🚀 Next Steps

1. **Explore Monitoring**: Visit your CloudWatch dashboard to see real-time metrics
2. **Ask Security Questions**: Use the natural language interface to analyze your data
3. **Review Documentation**: Check the [AWS Setup Guide](../AWS_SETUP_GUIDE.md) for advanced configuration
4. **Upload Real Data**: Replace synthetic data with your actual security logs and events
5. **Customize Analysis**: Modify analysis rules and AI prompts for your specific needs
6. **Set Up Alerts**: Configure SNS notifications for critical security events

## 🆘 Troubleshooting

### Common Issues

**AWS Credentials Not Working:**
```bash
# Check AWS configuration
aws configure list
aws sts get-caller-identity

# Reconfigure if needed
aws configure
```

**Bedrock Access Denied:**
```bash
# Check model access in AWS Console
aws bedrock list-foundation-models --region us-east-1

# Enable models manually in Bedrock console if needed
```

**CloudFormation Stack Failed:**
```bash
# Check stack events
aws cloudformation describe-stack-events --stack-name ai-security-analyst-infrastructure-dev

# Common causes:
# - Insufficient IAM permissions
# - Resource name conflicts
# - Service limits exceeded
```

**Athena Queries Failing:**
```bash
# Check workgroup configuration
aws athena get-work-group --work-group ai-security-analyst-workgroup-dev

# Verify S3 bucket permissions
aws s3 ls s3://your-security-data-bucket/

# Test simple query
aws athena start-query-execution \
  --query-string "SHOW TABLES" \
  --result-configuration OutputLocation=s3://your-athena-results-bucket/ \
  --work-group ai-security-analyst-workgroup-dev
```

**High AWS Costs:**
```bash
# Check current usage
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity DAILY \
  --metrics BlendedCost

# Review cost optimization settings
python src/python/aws_bedrock_athena_ai/cost_optimization/cost_optimizer.py --check-budget
```

### Getting Help

- **AWS Setup Guide**: [docs/AWS_SETUP_GUIDE.md](../AWS_SETUP_GUIDE.md)
- **Deployment Guide**: [src/python/aws_bedrock_athena_ai/infrastructure/DEPLOYMENT_GUIDE.md](../../src/python/aws_bedrock_athena_ai/infrastructure/DEPLOYMENT_GUIDE.md)
- **AWS Documentation**: [Bedrock](https://docs.aws.amazon.com/bedrock/) | [Athena](https://docs.aws.amazon.com/athena/)
- **Issues**: Create GitHub issue with logs and system info
- **AWS Support**: Use AWS Support if you have a support plan

## 🔒 Security Notes

- All data stays within your AWS account
- IAM roles use least-privilege access principles
- Encryption enabled at rest and in transit
- Pre-commit hooks prevent accidental secret commits
- Cost controls prevent unexpected charges
- Audit trails maintained in CloudTrail
- PII automatically redacted before AI analysis