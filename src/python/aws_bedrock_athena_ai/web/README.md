# Web Dashboard Module

⚠️ **Requires AWS Infrastructure Configuration**

This module provides an interactive web interface for security analysis and visualization.

## Features

- Real-time security metrics dashboard
- Interactive threat visualization
- Query interface for security data
- Compliance status monitoring

## AWS Requirements

- **AWS Infrastructure**: Deployed via CloudFormation
- **Amazon S3**: Security data storage
- **Amazon Athena**: Query execution
- **AWS Bedrock**: AI-powered analysis
- **IAM Permissions**: Full stack access

## Setup

1. Deploy AWS infrastructure: `python rose.py aws deploy`
2. Configure environment variables
3. Run: `python rose.py demo web`
4. Open browser to http://localhost:8000

## Usage

```bash
# Start web dashboard
python rose.py demo web

# Access at http://localhost:8000
```

## Status

✅ Implemented and tested
🔧 Requires AWS infrastructure deployment to run
