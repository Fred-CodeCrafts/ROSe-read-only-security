# ROSe AI Security Analyst

**ROSe (Read-Only Security) AI Security Analyst - Transform any organization into having a world-class cybersecurity analyst by combining AWS Bedrock's reasoning capabilities with Amazon Athena's data querying power.**

Ask your security data anything in plain English and get expert-level analysis and actionable recommendations instantly. This AI-powered security analyst operates in strictly read-only mode, providing comprehensive risk reports, threat intelligence, and governance insights without modifying systems or enforcing policies. All running within AWS Free Tier limits.

## 🔍 What ROSe AI Security Analyst Does

ROSe provides **analysis-only cybersecurity intelligence** powered by AWS services:

- **🧠 Natural Language Security Analysis** - Ask questions in plain English using AWS Bedrock's AI reasoning
- **� Smart Data Detective** - Automatically discovers and queries security data in S3 using Amazon Athena
- **🎯 Expert Threat Intelligence** - Advanced threat pattern recognition and risk assessment
- **📊 Instant Security Insights** - Executive summaries and technical details with business context
- **🛡️ Compliance Validation** - Automated compliance checking against security frameworks
- **� Real-time Monitoring** - CloudWatch dashboards and automated alerting
- **� Cost-Optimized Operations** - Intelligent query optimization to stay within AWS Free Tier

### AWS Services Integration

- **Amazon Bedrock** - AI reasoning engine for expert-level security analysis
- **Amazon Athena** - Serverless querying of security data stored in S3
- **Amazon S3** - Secure data lake for logs, configurations, and security events
- **AWS CloudFormation** - Infrastructure as code for consistent deployments
- **Amazon CloudWatch** - Monitoring, logging, and alerting for system health
- **AWS Lambda** - Serverless functions for automated monitoring and processing
- **Amazon EventBridge** - Event-driven automation and scheduling
- **AWS Glue** - Data catalog and schema management for security datasets
- **Amazon SNS** - Alert notifications via email and SMS
- **AWS IAM** - Fine-grained access control and security policies

## 🚫 What ROSe AI Security Analyst Does NOT Do

The system operates under strict **read-only principles**:

- ❌ **No System Modification** - Never changes code, configurations, or infrastructure
- ❌ **No Policy Enforcement** - Only reports violations, never enforces policies
- ❌ **No Autonomous Remediation** - Provides recommendations, requires human approval
- ❌ **No Production Deployment** - Analysis only, no infrastructure provisioning
- ❌ **No Destructive Operations** - Cannot delete, modify, or break existing systems
- ❌ **No Data Exfiltration** - All analysis stays within your AWS account

## 🏗️ Architecture

The ROSe AI Security Analyst uses **AWS-native architecture** for enterprise-grade security analysis:

```
┌─────────────────────────────────────────────────────────────┐
│               ROSe AI Security Analyst Platform            │
├─────────────────────────────────────────────────────────────┤
│  🧠 AWS Bedrock AI Engine     │  � Amazon Athena Queries   │
│  • Claude 3 Models            │  • Serverless SQL Analytics │
│  • Expert Security Reasoning  │  • Cost-Optimized Scanning  │
│  • Natural Language Interface │  • Cross-Source Correlation │
├─────────────────────────────────────────────────────────────┤
│  📊 Amazon S3 Data Lake       │  � CloudWatch Monitoring   │
│  • Security Events & Logs     │  • Real-time Dashboards     │
│  • System Configurations      │  • Automated Alerting       │
│  • Compliance Data            │  • Cost & Usage Tracking    │
├─────────────────────────────────────────────────────────────┤
│  ⚡ AWS Lambda Functions      │  🔐 IAM Security Controls   │
│  • Automated Processing       │  • Fine-grained Permissions │
│  • Event-driven Workflows     │  • Audit Trail Logging      │
│  • Custom Monitoring          │  • Encryption at Rest       │
├─────────────────────────────────────────────────────────────┤
│              🚀 CloudFormation Infrastructure              │
│         Automated deployment and resource management       │
└─────────────────────────────────────────────────────────────┘
```

### AWS Service Purposes

**Core AI & Analytics:**
- **Amazon Bedrock** - Provides Claude 3 models for expert-level security reasoning and natural language understanding
- **Amazon Athena** - Enables serverless SQL queries across massive security datasets without managing infrastructure
- **Amazon S3** - Serves as the secure, scalable data lake for all security logs, events, and configurations

**Infrastructure & Deployment:**
- **AWS CloudFormation** - Automates infrastructure deployment with infrastructure-as-code for consistency and repeatability
- **AWS Glue** - Manages data catalog and schema discovery for automatic table creation and data organization

**Monitoring & Operations:**
- **Amazon CloudWatch** - Provides real-time monitoring, custom dashboards, and automated alerting for system health
- **AWS Lambda** - Executes serverless functions for data processing, monitoring, and event-driven automation
- **Amazon EventBridge** - Orchestrates event-driven workflows and scheduled monitoring tasks

**Security & Notifications:**
- **AWS IAM** - Enforces least-privilege access controls and maintains comprehensive audit trails
- **Amazon SNS** - Delivers real-time alerts via email, SMS, and other notification channels

## 🚀 Getting Started

### Prerequisites

- **AWS Account** with administrative access
- **Python 3.8+** with pip
- **AWS CLI** installed and configured

### AWS Setup (15-30 minutes)

#### Option A: Automated Setup (Recommended)
```powershell
# Windows
.\scripts\aws-setup.ps1 -BucketPrefix "your-company" -Region "us-east-1"

# Linux/macOS
./scripts/aws-setup.sh --bucket-prefix "your-company" --region "us-east-1"
```

#### Option B: Manual Setup
Follow the detailed guide: [AWS Setup Guide](docs/AWS_SETUP_GUIDE.md)

### Configure AWS Credentials

1. **Install AWS CLI** (if not already installed):
   ```bash
   # Windows
   curl "https://awscli.amazonaws.com/AWSCLIV2.msi" -o "AWSCLIV2.msi"
   msiexec /i AWSCLIV2.msi
   
   # macOS
   curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
   sudo installer -pkg AWSCLIV2.pkg -target /
   
   # Linux
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

2. **Configure AWS credentials**:
   ```bash
   aws configure
   ```
   Enter your:
   - Access Key ID
   - Secret Access Key
   - Default region (e.g., `us-east-1`)
   - Default output format: `json`

### Enable Amazon Bedrock Models

1. Go to [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
2. Click "Model catalog" → Find "Claude 3 Haiku"
3. Click "Open in Playground" to automatically enable the model
4. If prompted, provide use case: "Security data analysis and threat detection"

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ai-security-analyst
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Deploy AWS infrastructure**:
   ```bash
   python src/python/aws_bedrock_athena_ai/infrastructure/deploy_infrastructure.py
   ```

4. **Validate setup**:
   ```bash
   python scripts/validate-aws-setup.py
   ```

### Basic Usage

**Start the ROSe AI Security Analyst**:
```bash
python -m src.python.aws_bedrock_athena_ai.cli
```

**Ask security questions**:
- "Are we being attacked right now?"
- "Show me failed login attempts from last week"
- "What's our biggest security risk?"
- "Check our compliance status"
- "Analyze suspicious network traffic patterns"

**Run security dashboard**:
```bash
python demo_ai_analyst.py
```

### Free Tier Optimization

The system is optimized for AWS Free Tier usage:

- **Amazon Bedrock**: Pay-per-use pricing (Claude 3 Haiku: ~$0.25 per 1M input tokens)
- **Amazon Athena**: 1TB of data scanned per month free
- **Amazon S3**: 5GB storage, 20,000 GET requests, 2,000 PUT requests
- **AWS Lambda**: 1M requests and 400,000 GB-seconds compute time
- **Amazon CloudWatch**: 10 custom metrics, 10 alarms, 5GB log ingestion

**Estimated monthly cost for typical usage**: $0-10

## 📁 Project Structure

```
rose-ai-security-analyst/
├── src/
│   └── python/
│       ├── aws_bedrock_athena_ai/     # Main ROSe AI Security Analyst
│       │   ├── nlp/                   # Natural language processing
│       │   ├── data_detective/        # Athena integration & correlation
│       │   ├── reasoning_engine/      # Bedrock AI integration
│       │   ├── insights/              # Report generation
│       │   ├── security/              # Security controls & monitoring
│       │   ├── cost_optimization/     # Free Tier optimization
│       │   ├── onboarding/            # User onboarding system
│       │   ├── api/                   # REST API interface
│       │   ├── web/                   # Web dashboard
│       │   ├── infrastructure/        # CloudFormation templates
│       │   └── config/                # AWS configuration
│       ├── integration/               # Legacy integration platform
│       ├── use_case_demo/             # Demo scenarios
│       ├── data_protection/           # Data privacy & redaction
│       └── ai_analyst/                # Core analysis engine
├── tests/
│   ├── unit/                          # Unit tests with property validation
│   └── integration/                   # End-to-end workflow tests
├── data/
│   ├── analysis/                      # Analysis results and context
│   └── synthetic/                     # Synthetic test data
├── scripts/                           # Setup and automation scripts
│   ├── aws-setup.ps1                  # Automated AWS setup
│   ├── validate-aws-setup.py          # Setup validation
│   └── deploy.ps1                     # Deployment automation
├── docs/
│   ├── AWS_SETUP_GUIDE.md             # Complete AWS setup guide
│   └── setup/                         # Additional setup documentation
└── .kiro/specs/                       # Spec-driven development artifacts
```

## 🧪 Testing

ROSe AI Security Analyst includes comprehensive testing with **property-based validation**:

**Run all tests**:
```bash
# Python tests for AWS integration
python -m pytest tests/unit/ -v

# Integration tests for end-to-end workflows
python -m pytest tests/integration/ -v

# Test AWS infrastructure deployment
python -m pytest src/python/aws_bedrock_athena_ai/tests/ -v
```

**Property-based testing** validates universal correctness properties:
- AWS service integration reliability
- Cost optimization effectiveness
- Security data processing accuracy
- Natural language query understanding
- Threat detection consistency
- Compliance validation correctness

**AWS-specific tests**:
```bash
# Test Bedrock integration
python -m pytest src/python/aws_bedrock_athena_ai/tests/test_reasoning_engine.py -v

# Test Athena queries
python -m pytest src/python/aws_bedrock_athena_ai/tests/test_data_detective.py -v

# Test cost optimization
python -m pytest src/python/aws_bedrock_athena_ai/tests/test_cost_optimization.py -v
```

## 🔧 Configuration

### AWS Configuration

The system automatically generates configuration files after deployment:

```yaml
# config/aws_config_dev.json
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

### CloudWatch Monitoring

Access your monitoring dashboard at:
```
https://console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=ai-security-analyst-dashboard-{environment}
```

The dashboard includes:
- **Athena Query Metrics**: Data scanned, execution time, costs
- **S3 Storage Metrics**: Data lake size and growth
- **Application Logs**: Error tracking and performance metrics
- **Bedrock Usage**: AI model invocation costs and performance

### Alert Configuration

The system automatically creates alerts for:
- **High Athena costs** (>10GB data scanned per hour)
- **Application errors** (>10 errors per 5 minutes)
- **Storage growth** (>5GB in S3 data lake)
- **Bedrock usage** (approaching cost thresholds)

## 📊 Use Cases

### 1. Natural Language Security Analysis
```bash
python -m src.python.aws_bedrock_athena_ai.cli
```
**Example interactions:**
- **User**: "Are we being attacked right now?"
- **AI**: "Analyzing current security events... Found 3 concerning patterns:
  1. 15 failed logins from IP 203.0.113.50 targeting admin accounts
  2. Successful login from new geographic location for user 'john.doe'
  3. Multiple service accounts accessed outside business hours
  Recommendation: Investigate IP 203.0.113.50 immediately..."

### 2. Threat Intelligence & Risk Assessment
```bash
python -m src.python.aws_bedrock_athena_ai.reasoning_engine.expert_reasoning_engine
```
- Advanced threat pattern recognition using AWS Bedrock
- Risk scoring and prioritization with business context
- Automated threat hunting across multiple data sources
- Executive-friendly risk summaries with technical details

### 3. Compliance Monitoring
```bash
python -m src.python.aws_bedrock_athena_ai.insights.report_generator
```
- **SOX compliance**: Access controls and audit logging validation
- **PCI DSS**: Payment data security assessment
- **GDPR**: Data privacy and protection analysis
- **SOC 2**: Security controls effectiveness evaluation

### 4. Security Data Correlation
```bash
python -m src.python.aws_bedrock_athena_ai.data_detective.smart_data_detective
```
- Cross-source event correlation using Amazon Athena
- Timeline analysis of security incidents
- Automatic discovery of related security events
- Pattern detection across logs, configs, and events

### 5. Cost-Optimized Security Operations
```bash
python -m src.python.aws_bedrock_athena_ai.cost_optimization.cost_optimizer
```
- Intelligent query optimization for AWS Free Tier
- Automated cost monitoring and alerting
- Smart caching to reduce Bedrock API calls
- Usage tracking and budget management

## 🛡️ Security & Privacy

ROSe AI Security Analyst prioritizes security and privacy with AWS-native controls:

- **🔒 Read-Only Operations** - Never modifies target systems or data
- **🏠 AWS Account Isolation** - All analysis stays within your AWS account
- **🔐 Encryption Everywhere** - Data encrypted at rest (S3) and in transit (TLS)
- **🎭 Automatic PII Redaction** - Sensitive data automatically redacted before AI analysis
- **📝 Complete Audit Trails** - All operations logged in CloudWatch with full traceability
- **🚫 No Data Exfiltration** - Analysis results never leave your AWS environment
- **🔑 IAM-Based Access Control** - Fine-grained permissions with least-privilege principles
- **📊 Cost Transparency** - Real-time cost monitoring with automated budget alerts

### AWS Security Features

- **VPC Isolation** - Optional VPC deployment for network-level security
- **CloudTrail Integration** - Complete API audit logging
- **KMS Encryption** - Customer-managed encryption keys support
- **IAM Roles** - Service-to-service authentication without long-lived credentials
- **Resource-Based Policies** - Granular access control at the resource level

## 🤝 Contributing

ROSe AI Security Analyst follows **Spec-Driven Development (SDD)**:

1. **Requirements** - Define what needs to be built
2. **Design** - Specify how it will be built using AWS services
3. **Tasks** - Break down implementation steps
4. **Property-Based Testing** - Validate correctness properties

See `.kiro/specs/aws-bedrock-athena-ai/` for complete specifications.

### Development Setup

```bash
# Set up git hooks for security
.\scripts\setup-git-hooks.ps1

# Deploy development AWS infrastructure
python src/python/aws_bedrock_athena_ai/infrastructure/deploy_infrastructure.py --environment dev

# Run comprehensive test suite
python -m pytest tests/ -v --tb=short

# Test AWS integration
python scripts/validate-aws-setup.py
```

### AWS Development Best Practices

- Use separate AWS accounts for dev/staging/prod
- Enable CloudTrail for all development activities
- Implement cost budgets and alerts for development
- Use IAM roles instead of access keys where possible
- Test with minimal IAM permissions to ensure least privilege

## 📄 License

ROSe AI Security Analyst is open-source software. See LICENSE file for details.

## 🆘 Support

- **AWS Setup Guide**: [docs/AWS_SETUP_GUIDE.md](docs/AWS_SETUP_GUIDE.md)
- **Deployment Guide**: [src/python/aws_bedrock_athena_ai/infrastructure/DEPLOYMENT_GUIDE.md](src/python/aws_bedrock_athena_ai/infrastructure/DEPLOYMENT_GUIDE.md)
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **AWS Documentation**: [AWS Bedrock](https://docs.aws.amazon.com/bedrock/) | [Amazon Athena](https://docs.aws.amazon.com/athena/)

## 💰 Cost Estimation

**AWS Free Tier (Monthly)**:
- Amazon Bedrock: Pay-per-use (~$0.25 per 1M tokens)
- Amazon Athena: 1TB data scanned free
- Amazon S3: 5GB storage free
- AWS Lambda: 1M requests free
- CloudWatch: 10 metrics, 10 alarms free

**Typical monthly cost**: $0-10 for small to medium organizations

---

**ROSe AI Security Analyst** - *Transform your organization into having world-class cybersecurity expertise with AWS AI*