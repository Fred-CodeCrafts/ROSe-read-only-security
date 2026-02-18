# Smart Data Detective Module

⚠️ **Requires AWS Athena + S3 Configuration**

This module provides intelligent data discovery and correlation across AWS security data sources.

## Features

- Automatic discovery of security data sources in S3
- Optimized Athena query generation
- Cross-source event correlation
- Timeline analysis and pattern detection

## AWS Requirements

- **Amazon Athena**: Serverless SQL queries
- **Amazon S3**: Security data lake
- **AWS Glue**: Data catalog (optional)
- **IAM Permissions**: `athena:*`, `s3:GetObject`, `glue:GetTable`

## Setup

1. Deploy AWS infrastructure: `python rose.py aws deploy`
2. Upload security data to S3
3. Configure Athena workgroup
4. Run: `python rose.py chat`

## Usage

```python
from data_detective.smart_data_detective import SmartDataDetective

detective = SmartDataDetective()
sources = detective.discover_data_sources()
results = detective.correlate_events(sources)
```

## Status

✅ Implemented and tested
🔧 Requires AWS Athena + S3 configuration to run
