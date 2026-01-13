# AWS Setup Script for AI Security Analyst
# This script automates the AWS infrastructure setup

param(
    [Parameter(Mandatory=$true)]
    [string]$BucketPrefix,
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-east-1"
)

Write-Host "🚀 Setting up AWS infrastructure for AI Security Analyst..." -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Bucket Prefix: $BucketPrefix" -ForegroundColor Yellow

# Check if AWS CLI is installed
try {
    aws --version | Out-Null
    Write-Host "✅ AWS CLI is installed" -ForegroundColor Green
} catch {
    Write-Host "❌ AWS CLI is not installed. Please install it first." -ForegroundColor Red
    Write-Host "Download from: https://aws.amazon.com/cli/" -ForegroundColor Yellow
    exit 1
}

# Check if AWS credentials are configured
try {
    aws sts get-caller-identity | Out-Null
    Write-Host "✅ AWS credentials are configured" -ForegroundColor Green
} catch {
    Write-Host "❌ AWS credentials not configured. Run 'aws configure' first." -ForegroundColor Red
    exit 1
}

$SecurityBucket = "$BucketPrefix-security-data-lake"
$AthenaBucket = "$BucketPrefix-athena-results"

Write-Host "`n📦 Creating S3 buckets..." -ForegroundColor Cyan

# Create security data bucket
try {
    aws s3 mb "s3://$SecurityBucket" --region $Region
    Write-Host "✅ Created security data bucket: $SecurityBucket" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Bucket $SecurityBucket might already exist or name is taken" -ForegroundColor Yellow
}

# Create Athena results bucket
try {
    aws s3 mb "s3://$AthenaBucket" --region $Region
    Write-Host "✅ Created Athena results bucket: $AthenaBucket" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Bucket $AthenaBucket might already exist or name is taken" -ForegroundColor Yellow
}

# Create folder structure in security bucket
Write-Host "`n📁 Creating folder structure..." -ForegroundColor Cyan

$folders = @(
    "security-logs/",
    "access-logs/", 
    "firewall-logs/",
    "cloudtrail-logs/",
    "system-configs/",
    "vulnerability-scans/",
    "processed-data/"
)

foreach ($folder in $folders) {
    try {
        # Create empty object to represent folder
        aws s3api put-object --bucket $SecurityBucket --key $folder --region $Region
        Write-Host "✅ Created folder: $folder" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Could not create folder: $folder" -ForegroundColor Yellow
    }
}

# Create Athena database
Write-Host "`n🗄️  Setting up Athena database..." -ForegroundColor Cyan

# Create temporary SQL file
$sqlFile = "temp_athena_setup.sql"
$createDbSql = @"
CREATE DATABASE IF NOT EXISTS security_analytics
COMMENT 'Database for AI Security Analyst';
"@

$createDbSql | Out-File -FilePath $sqlFile -Encoding UTF8

try {
    # Execute Athena query
    $queryId = aws athena start-query-execution `
        --query-string $createDbSql `
        --result-configuration "OutputLocation=s3://$AthenaBucket/" `
        --region $Region `
        --query 'QueryExecutionId' `
        --output text

    Write-Host "✅ Athena database creation started (Query ID: $queryId)" -ForegroundColor Green
    
    # Wait for query to complete
    do {
        Start-Sleep -Seconds 2
        $status = aws athena get-query-execution --query-execution-id $queryId --region $Region --query 'QueryExecution.Status.State' --output text
        Write-Host "   Database creation status: $status" -ForegroundColor Yellow
    } while ($status -eq "RUNNING")
    
    if ($status -eq "SUCCEEDED") {
        Write-Host "✅ Athena database created successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Athena database creation failed" -ForegroundColor Red
    }
    
} catch {
    Write-Host "⚠️  Could not create Athena database. You may need to set up Athena manually." -ForegroundColor Yellow
}

# Clean up temp file
Remove-Item $sqlFile -ErrorAction SilentlyContinue

# Create sample security events data
Write-Host "`n📄 Creating sample security data..." -ForegroundColor Cyan

$sampleData = @"
{"timestamp": "2024-01-15T10:00:00Z", "event_type": "LOGIN_ATTEMPT", "severity": "INFO", "source_ip": "192.168.1.100", "user_id": "user123", "action": "LOGIN", "result": "SUCCESS", "description": "User login successful"}
{"timestamp": "2024-01-15T10:05:00Z", "event_type": "FAILED_LOGIN", "severity": "WARNING", "source_ip": "203.0.113.50", "user_id": "admin", "action": "LOGIN", "result": "FAILED", "description": "Failed login attempt"}
{"timestamp": "2024-01-15T10:06:00Z", "event_type": "BRUTE_FORCE_DETECTED", "severity": "HIGH", "source_ip": "203.0.113.50", "user_id": "admin", "action": "MULTIPLE_LOGIN", "result": "BLOCKED", "description": "Multiple failed login attempts detected"}
{"timestamp": "2024-01-15T10:10:00Z", "event_type": "MALWARE_DETECTED", "severity": "CRITICAL", "source_ip": "10.0.0.50", "user_id": "system", "action": "SCAN", "result": "QUARANTINED", "description": "Malware detected and quarantined"}
{"timestamp": "2024-01-15T10:15:00Z", "event_type": "UNAUTHORIZED_ACCESS", "severity": "HIGH", "source_ip": "203.0.113.75", "user_id": "unknown", "action": "FILE_ACCESS", "result": "DENIED", "description": "Unauthorized file access attempt"}
"@

$sampleFile = "sample_security_events.json"
$sampleData | Out-File -FilePath $sampleFile -Encoding UTF8

try {
    aws s3 cp $sampleFile "s3://$SecurityBucket/security-logs/year=2024/month=01/day=15/" --region $Region
    Write-Host "✅ Uploaded sample security data" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not upload sample data" -ForegroundColor Yellow
}

Remove-Item $sampleFile -ErrorAction SilentlyContinue

# Update configuration file
Write-Host "`n⚙️  Updating configuration..." -ForegroundColor Cyan

$configPath = "src/python/aws_bedrock_athena_ai/config/aws_config.py"
$configContent = @"
"""
AWS Configuration for AI Security Analyst
Auto-generated by setup script
"""

AWS_CONFIG = {
    'region': '$Region',
    'security_data_bucket': '$SecurityBucket',
    'athena_results_bucket': '$AthenaBucket',
    'athena_database': 'security_analytics',
    'bedrock_models': {
        'fast': 'anthropic.claude-3-haiku-20240307-v1:0',
        'balanced': 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        'powerful': 'anthropic.claude-3-opus-20240229-v1:0'
    },
    'free_tier_limits': {
        's3_storage_gb': 5,
        'athena_query_gb_per_month': 10000,  # 10TB
        'max_query_cost_usd': 0.10
    }
}

# Environment-specific overrides
import os

if os.getenv('AWS_REGION'):
    AWS_CONFIG['region'] = os.getenv('AWS_REGION')

if os.getenv('SECURITY_DATA_BUCKET'):
    AWS_CONFIG['security_data_bucket'] = os.getenv('SECURITY_DATA_BUCKET')

if os.getenv('ATHENA_RESULTS_BUCKET'):
    AWS_CONFIG['athena_results_bucket'] = os.getenv('ATHENA_RESULTS_BUCKET')
"@

try {
    $configContent | Out-File -FilePath $configPath -Encoding UTF8
    Write-Host "✅ Updated configuration file: $configPath" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Could not update configuration file" -ForegroundColor Yellow
}

# Display next steps
Write-Host "`n🎉 AWS Infrastructure Setup Complete!" -ForegroundColor Green
Write-Host "`n📋 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Enable AWS Bedrock model access in the AWS Console:" -ForegroundColor White
Write-Host "   - Go to AWS Bedrock console" -ForegroundColor Gray
Write-Host "   - Click 'Model access' → 'Request model access'" -ForegroundColor Gray
Write-Host "   - Request access to Claude models" -ForegroundColor Gray
Write-Host "   - Wait for approval (can take 1-24 hours)" -ForegroundColor Gray

Write-Host "`n2. Test the setup:" -ForegroundColor White
Write-Host "   aws athena start-query-execution --query-string `"SELECT * FROM security_analytics.security_events LIMIT 5`" --result-configuration `"OutputLocation=s3://$AthenaBucket/`" --region $Region" -ForegroundColor Gray

Write-Host "`n3. Run the AI Security Analyst:" -ForegroundColor White
Write-Host "   python -m aws_bedrock_athena_ai.cli" -ForegroundColor Gray

Write-Host "`n📊 Resources Created:" -ForegroundColor Cyan
Write-Host "• S3 Bucket: $SecurityBucket" -ForegroundColor White
Write-Host "• S3 Bucket: $AthenaBucket" -ForegroundColor White
Write-Host "• Athena Database: security_analytics" -ForegroundColor White
Write-Host "• Sample security data uploaded" -ForegroundColor White

Write-Host "`n💰 Estimated Monthly Cost: `$0-5 (within Free Tier for light usage)" -ForegroundColor Green
Write-Host "`n⚠️  Remember to:" -ForegroundColor Yellow
Write-Host "• Set up billing alerts in AWS Console" -ForegroundColor White
Write-Host "• Review IAM permissions for security" -ForegroundColor White
Write-Host "• Monitor usage to stay within Free Tier" -ForegroundColor White

Write-Host "`n🔗 Useful Links:" -ForegroundColor Cyan
Write-Host "• AWS Bedrock Console: https://console.aws.amazon.com/bedrock/" -ForegroundColor Blue
Write-Host "• Athena Console: https://console.aws.amazon.com/athena/" -ForegroundColor Blue
Write-Host "• S3 Console: https://console.aws.amazon.com/s3/" -ForegroundColor Blue
Write-Host "• Setup Guide: docs/AWS_SETUP_GUIDE.md" -ForegroundColor Blue