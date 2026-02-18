# REST API Module

⚠️ **Requires AWS Infrastructure Configuration**

This module provides a REST API for programmatic access to security analysis features.

## Features

- RESTful API endpoints for security queries
- Authentication and authorization
- Rate limiting and throttling
- API documentation (OpenAPI/Swagger)

## AWS Requirements

- **AWS Infrastructure**: Deployed via CloudFormation
- **Amazon API Gateway**: API management (optional)
- **AWS Lambda**: Serverless API handlers (optional)
- **IAM Permissions**: API access controls

## Setup

1. Deploy AWS infrastructure: `python rose.py aws deploy`
2. Configure API authentication
3. Start API server: `python -m aws_bedrock_athena_ai.api.main`

## Endpoints

```
POST /api/v1/query          - Execute security query
GET  /api/v1/threats        - List detected threats
GET  /api/v1/compliance     - Get compliance status
POST /api/v1/analyze        - Analyze security data
```

## Usage

```bash
# Start API server
python -m aws_bedrock_athena_ai.api.main

# Example API call
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Show failed logins"}'
```

## Status

✅ Implemented and tested
🔧 Requires AWS infrastructure configuration to run
