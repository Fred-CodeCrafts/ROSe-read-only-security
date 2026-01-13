# AWS Console Setup Guide for AI Security Analyst

This guide walks you through setting up all the required AWS services in the AWS Console to run the AI Security Analyst system.

## Prerequisites

- AWS Account with administrative access
- Credit card on file (for services beyond Free Tier)
- Basic familiarity with AWS Console

## Estimated Setup Time: 30-45 minutes

---

## Step 1: Set Up AWS Bedrock (Simplified!)

### 1.1 Navigate to Bedrock Service
1. Log into AWS Console
2. Search for "Bedrock" in the services search bar
3. Click on "Amazon Bedrock"
4. Select your preferred region (recommend **us-east-1** or **us-west-2** for best model availability)

### 1.2 Model Access (Now Automatic!)
**🎉 Great News**: AWS has simplified model access! Foundation models are now **automatically enabled** when first invoked in your account.

**What this means for you:**
- No more manual model access requests for most models
- Models activate instantly when you first use them
- For Anthropic Claude models, first-time users may need to submit use case details

**To test model access:**
1. Go to the Bedrock console
2. Click **"Model catalog"** in the left sidebar
3. Find **"Claude 3 Haiku"** and click on it
4. Click **"Open in Playground"**
5. If prompted for use case details, fill out:
   - **Use case**: "Security data analysis and threat detection"
   - **Company**: Your company name
   - **Industry**: Select appropriate industry

**✅ If you can access the playground, you're ready to go!**

---

## Step 2: Create S3 Buckets for Security Data

### 2.1 Create Main Security Data Bucket
1. Navigate to **S3** service
2. Click **"Create bucket"**
3. Configure bucket:
   - **Bucket name**: `your-company-security-data-lake` (must be globally unique)
   - **Region**: Same as Bedrock region
   - **Block Public Access**: Keep all boxes checked (recommended)
   - **Bucket Versioning**: Enable (recommended)
   - **Default encryption**: Enable with SSE-S3
4. Click **"Create bucket"**

### 2.2 Create Folder Structure
1. Open your new bucket
2. Create the following folders by clicking **"Create folder"**:
   ```
   security-logs/
   access-logs/
   firewall-logs/
   cloudtrail-logs/
   system-configs/
   vulnerability-scans/
   processed-data/
   ```

### 2.3 Create Athena Results Bucket
1. Create another bucket: `your-company-athena-results`
2. Same settings as above
3. This will store Athena query results

---

## Step 3: Set Up Amazon Athena

### 3.1 Navigate to Athena
1. Go to **Amazon Athena** service
2. If first time, you'll see a "Get Started" page

### 3.2 Configure Query Result Location
1. Click **"Settings"** tab
2. Click **"Manage"**
3. Set **Query result location**: `s3://your-company-athena-results/`
4. Click **"Save"**

### 3.3 Create Security Database
1. Go to **"Query editor"** tab
2. Run this SQL command:
   ```sql
   CREATE DATABASE security_analytics
   COMMENT 'Database for security data analysis';
   ```
3. Click **"Run query"**

### 3.4 Create Sample Security Tables
Run these commands one by one:

```sql
-- Security Events Table
CREATE EXTERNAL TABLE security_analytics.security_events (
    timestamp string,
    event_type string,
    severity string,
    source_ip string,
    destination_ip string,
    user_id string,
    action string,
    result string,
    description string,
    raw_log string
)
PARTITIONED BY (
    year string,
    month string,
    day string
)
STORED AS PARQUET
LOCATION 's3://your-company-security-data-lake/security-logs/'
TBLPROPERTIES ('has_encrypted_data'='false');
```

```sql
-- Access Logs Table
CREATE EXTERNAL TABLE security_analytics.access_logs (
    timestamp string,
    user_id string,
    source_ip string,
    resource string,
    method string,
    status_code string,
    user_agent string,
    session_id string
)
PARTITIONED BY (
    year string,
    month string,
    day string
)
STORED AS PARQUET
LOCATION 's3://your-company-security-data-lake/access-logs/'
TBLPROPERTIES ('has_encrypted_data'='false');
```

```sql
-- System Configurations Table
CREATE EXTERNAL TABLE security_analytics.system_configs (
    system_id string,
    config_type string,
    setting_name string,
    setting_value string,
    compliance_status string,
    last_modified timestamp
)
PARTITIONED BY (
    system_type string
)
STORED AS PARQUET
LOCATION 's3://your-company-security-data-lake/system-configs/'
TBLPROPERTIES ('has_encrypted_data'='false');
```

---

## Step 4: Create IAM Role for the Application

### 4.1 Create IAM Role
1. Navigate to **IAM** service
2. Click **"Roles"** in left sidebar
3. Click **"Create role"**
4. Select **"AWS service"**
5. Choose **"EC2"** (we'll modify this later)
6. Click **"Next"**

### 4.2 Attach Policies
Search for and attach these policies:
- `AmazonS3FullAccess` (or create custom policy for your buckets)
- `AmazonAthenaFullAccess`
- `AmazonBedrockFullAccess`
- `CloudWatchLogsFullAccess`

### 4.3 Name and Create Role
1. **Role name**: `AISecurityAnalystRole`
2. **Description**: "Role for AI Security Analyst application"
3. Click **"Create role"**

### 4.4 Create Custom Policy (Recommended)
For better security, create a custom policy instead of using full access:

1. Go to **"Policies"** in IAM
2. Click **"Create policy"**
3. Use JSON editor and paste:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::your-company-security-data-lake",
                "arn:aws:s3:::your-company-security-data-lake/*",
                "arn:aws:s3:::your-company-athena-results",
                "arn:aws:s3:::your-company-athena-results/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "athena:StartQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:StopQueryExecution",
                "athena:GetWorkGroup",
                "athena:ListQueryExecutions"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:ListFoundationModels"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "glue:GetTable",
                "glue:GetDatabase",
                "glue:GetPartitions"
            ],
            "Resource": "*"
        }
    ]
}
```

4. Name it `AISecurityAnalystPolicy`
5. Attach this policy to your role instead of the full access policies

---

## Step 5: Set Up AWS CLI and Credentials

### 5.1 Create Access Keys
1. In IAM, go to **"Users"**
2. Click your username (or create a new user)
3. Go to **"Security credentials"** tab
4. Click **"Create access key"**
5. Choose **"Command Line Interface (CLI)"**
6. Download the CSV file with your keys

### 5.2 Install AWS CLI (if not installed)
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

### 5.3 Configure AWS CLI
```bash
aws configure
```
Enter:
- **Access Key ID**: From your downloaded CSV
- **Secret Access Key**: From your downloaded CSV
- **Default region**: Same region you used for other services
- **Default output format**: `json`

---

## Step 6: Upload Sample Security Data

### 6.1 Create Sample Data Files
Create these sample files locally:

**sample_security_events.json**:
```json
{"timestamp": "2024-01-15T10:00:00Z", "event_type": "LOGIN_ATTEMPT", "severity": "INFO", "source_ip": "192.168.1.100", "user_id": "user123", "action": "LOGIN", "result": "SUCCESS", "description": "User login successful"}
{"timestamp": "2024-01-15T10:05:00Z", "event_type": "FAILED_LOGIN", "severity": "WARNING", "source_ip": "203.0.113.50", "user_id": "admin", "action": "LOGIN", "result": "FAILED", "description": "Failed login attempt"}
{"timestamp": "2024-01-15T10:06:00Z", "event_type": "BRUTE_FORCE_DETECTED", "severity": "HIGH", "source_ip": "203.0.113.50", "user_id": "admin", "action": "MULTIPLE_LOGIN", "result": "BLOCKED", "description": "Multiple failed login attempts detected"}
```

### 6.2 Upload Sample Data
```bash
# Upload sample security events
aws s3 cp sample_security_events.json s3://your-company-security-data-lake/security-logs/year=2024/month=01/day=15/

# Create more sample data for other tables as needed
```

---

## Step 7: Test the Setup

### 7.1 Test Athena Query
In Athena console, run:
```sql
SELECT * FROM security_analytics.security_events 
WHERE year='2024' AND month='01' AND day='15'
LIMIT 10;
```

### 7.2 Test Bedrock Access (once approved)
You can test this with AWS CLI:
```bash
aws bedrock list-foundation-models --region us-east-1
```

---

## Step 8: Configure Application Settings

### 8.1 Update Configuration File
Edit `src/python/aws_bedrock_athena_ai/config/aws_config.py`:

```python
AWS_CONFIG = {
    'region': 'us-east-1',  # Your chosen region
    'security_data_bucket': 'your-company-security-data-lake',
    'athena_results_bucket': 'your-company-athena-results',
    'athena_database': 'security_analytics',
    'bedrock_models': {
        'fast': 'anthropic.claude-3-haiku-20240307-v1:0',
        'balanced': 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'powerful': 'anthropic.claude-3-opus-20240229-v1:0'
    }
}
```

---

## Step 9: Verify Free Tier Usage

### 9.1 Set Up Billing Alerts
1. Go to **AWS Billing Console**
2. Click **"Billing preferences"**
3. Enable **"Receive Billing Alerts"**
4. Go to **CloudWatch** → **Alarms**
5. Create alarm for billing > $10 (or your preferred threshold)

### 9.2 Monitor Usage
- **S3**: 5GB free storage
- **Athena**: 10TB query data scanned per month
- **Bedrock**: Varies by model (check current pricing)

---

## Troubleshooting

### Common Issues:

1. **Bedrock Access Denied**
   - Ensure model access is approved
   - Check IAM permissions
   - Verify region supports Bedrock

2. **Athena Query Fails**
   - Check S3 bucket permissions
   - Verify table schema matches data
   - Ensure query result location is set

3. **S3 Access Denied**
   - Check bucket policies
   - Verify IAM role permissions
   - Ensure bucket names are correct

### Getting Help:
- AWS Documentation: https://docs.aws.amazon.com/
- AWS Support (if you have a support plan)
- AWS Community Forums

---

## Next Steps

Once setup is complete:
1. Run the AI Security Analyst application
2. Upload your actual security data
3. Start asking security questions!
4. Monitor costs and optimize as needed

## Security Best Practices

- Use least-privilege IAM policies
- Enable CloudTrail for audit logging
- Encrypt data at rest and in transit
- Regularly rotate access keys
- Monitor for unusual activity

---

**Total Estimated Monthly Cost (Free Tier)**: $0-5 for light usage
**Setup Complete!** 🎉

Your AI Security Analyst is now ready to analyze your security data with the power of AWS Bedrock and Athena!