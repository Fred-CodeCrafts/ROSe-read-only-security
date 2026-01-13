# AI Security Analyst - Deployment Guide

This guide walks you through deploying the complete AI Security Analyst infrastructure on AWS with monitoring and alerting capabilities.

## Prerequisites

### AWS Account Setup
- AWS account with appropriate permissions
- AWS CLI configured with credentials
- Python 3.9+ installed
- boto3 library installed (`pip install boto3`)

### Required AWS Permissions
Your AWS user/role needs the following permissions:
- CloudFormation: Full access
- S3: Full access
- Athena: Full access
- Glue: Full access
- Bedrock: Model access
- IAM: Role and policy management
- CloudWatch: Logs, metrics, and alarms
- SNS: Topic management
- Lambda: Function management
- EventBridge: Rule management

## Quick Start

### 1. Deploy Infrastructure

```bash
# Basic deployment
python deploy_infrastructure.py

# With custom project name and environment
python deploy_infrastructure.py --project-name my-security-analyst --environment prod

# With email alerts
python deploy_infrastructure.py --email your-email@example.com
```

### 2. Verify Deployment

```bash
# Verify existing deployment
python deploy_infrastructure.py --verify-only
```

## Deployed Resources

### Core Infrastructure
- **S3 Buckets**: Security data lake and Athena query results
- **Glue Database**: Security data catalog with predefined tables
- **Athena Workgroup**: Cost-controlled query execution
- **IAM Roles**: Secure access to AWS services

### Monitoring & Alerting
- **CloudWatch Dashboard**: Real-time monitoring of system metrics
- **CloudWatch Alarms**: Automated alerts for cost and error thresholds
- **SNS Topic**: Email and SMS alert delivery
- **Lambda Function**: Custom monitoring and health checks
- **Log Groups**: Centralized application logging

### Security Features
- **Encryption**: All data encrypted at rest and in transit
- **Access Control**: Least-privilege IAM policies
- **Cost Controls**: Free Tier optimization and spending limits
- **Audit Logging**: Complete audit trail of all operations

## Configuration

After deployment, the system generates a configuration file at:
```
config/aws_config_{environment}.json
```

This file contains all the resource identifiers needed by the application.

### Sample Configuration
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
  "monitoring": {
    "dashboard_url": "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=ai-security-analyst-dashboard-dev"
  },
  "application": {
    "cost_limits": {
      "max_query_cost_usd": 0.05,
      "daily_budget_usd": 1.00,
      "athena_data_scan_limit_gb": 10.0
    }
  }
}
```

## Monitoring Setup

### CloudWatch Dashboard
Access your monitoring dashboard at:
```
https://console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name={project-name}-dashboard-{environment}
```

The dashboard includes:
- **Athena Query Metrics**: Data scanned, execution time, costs
- **S3 Storage Metrics**: Data lake size and growth
- **Application Logs**: Error tracking and performance metrics

### Alerts Configuration

The system automatically creates the following alerts:

#### High Athena Cost Alarm
- **Trigger**: When data scanning exceeds 10GB per hour
- **Purpose**: Prevent unexpected charges
- **Action**: Sends alert to SNS topic

#### Application Error Alarm
- **Trigger**: When error rate exceeds 10 errors per 5 minutes
- **Purpose**: Detect application issues
- **Action**: Sends alert to SNS topic

#### Storage Growth Alarm
- **Trigger**: When S3 storage exceeds 5GB
- **Purpose**: Monitor data growth
- **Action**: Sends alert to SNS topic

### Email Notifications

To receive email alerts:

1. **During Deployment**: Use the `--email` parameter
   ```bash
   python deploy_infrastructure.py --email your-email@example.com
   ```

2. **After Deployment**: Subscribe manually via AWS Console
   - Go to SNS in AWS Console
   - Find your alerts topic: `{project-name}-alerts-{environment}`
   - Create email subscription
   - Confirm subscription via email

## Data Setup

### Directory Structure
The deployment creates the following S3 directory structure:

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

### Data Formats
The system expects data in Parquet format with the following schemas:

#### Security Events Table
```sql
CREATE EXTERNAL TABLE security_events (
    timestamp string,
    event_type string,
    source_ip string,
    destination_ip string,
    user_id string,
    action string,
    result string,
    severity string,
    raw_log string
)
PARTITIONED BY (year string, month string, day string)
```

#### System Configurations Table
```sql
CREATE EXTERNAL TABLE system_configs (
    system_id string,
    config_type string,
    setting_name string,
    setting_value string,
    last_modified timestamp,
    compliance_status string
)
PARTITIONED BY (system_type string)
```

## Cost Optimization

### Free Tier Limits
The infrastructure is optimized for AWS Free Tier:

- **Athena**: 1TB data scanned per month
- **S3**: 5GB storage, 20,000 GET requests, 2,000 PUT requests
- **Lambda**: 1M requests, 400,000 GB-seconds compute
- **CloudWatch**: 10 custom metrics, 10 alarms, 5GB log ingestion

### Cost Controls
- **Query Limits**: 1GB per query maximum
- **Workgroup Enforcement**: Prevents expensive queries
- **Lifecycle Policies**: Automatic data archival
- **Monitoring Alerts**: Early warning for cost overruns

## Troubleshooting

### Common Issues

#### 1. CloudFormation Stack Creation Failed
```bash
# Check stack events
aws cloudformation describe-stack-events --stack-name ai-security-analyst-infrastructure-dev

# Common causes:
# - Insufficient IAM permissions
# - Resource name conflicts
# - Service limits exceeded
```

#### 2. Bedrock Access Denied
```bash
# Enable Bedrock model access in AWS Console
# Go to Bedrock > Model access > Request model access
# Enable Claude models for your region
```

#### 3. Athena Query Failures
```bash
# Check workgroup configuration
aws athena get-work-group --work-group ai-security-analyst-workgroup-dev

# Verify S3 bucket permissions
aws s3 ls s3://your-security-data-bucket/
```

#### 4. Monitoring Function Errors
```bash
# Check Lambda function logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/ai-security-analyst-monitoring

# Test function manually
aws lambda invoke --function-name ai-security-analyst-monitoring-dev response.json
```

### Log Analysis
Application logs are stored in CloudWatch:
```
/aws/ai-security-analyst/{project-name}-{environment}
```

Use CloudWatch Insights to query logs:
```sql
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 100
```

## Security Best Practices

### IAM Roles
- Use least-privilege access
- Regularly rotate access keys
- Enable CloudTrail for audit logging

### Data Protection
- All S3 buckets have encryption enabled
- Public access is blocked by default
- VPC endpoints recommended for production

### Network Security
- Use VPC endpoints for AWS service access
- Implement security groups and NACLs
- Consider AWS PrivateLink for enhanced security

## Scaling Considerations

### Production Deployment
For production environments:

1. **Multi-AZ Setup**: Deploy across multiple availability zones
2. **VPC Configuration**: Use private subnets and VPC endpoints
3. **Enhanced Monitoring**: Add custom metrics and detailed logging
4. **Backup Strategy**: Implement cross-region replication
5. **Disaster Recovery**: Plan for data and configuration recovery

### Performance Optimization
- Use columnar formats (Parquet) for better query performance
- Implement data partitioning by date and system type
- Consider data compression to reduce storage costs
- Use Athena query result caching

## Support and Maintenance

### Regular Tasks
- Monitor CloudWatch dashboards weekly
- Review cost reports monthly
- Update IAM policies as needed
- Test disaster recovery procedures quarterly

### Updates and Patches
- Keep Lambda runtime updated
- Monitor AWS service announcements
- Update CloudFormation templates as needed
- Review and update security policies

## Additional Resources

- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Amazon Athena User Guide](https://docs.aws.amazon.com/athena/)
- [AWS CloudFormation Documentation](https://docs.aws.amazon.com/cloudformation/)
- [AWS Free Tier Details](https://aws.amazon.com/free/)

For technical support, refer to the application logs and AWS documentation, or contact your system administrator.