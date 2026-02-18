# Natural Language Processing Module

⚠️ **Requires AWS Bedrock Configuration**

This module provides natural language understanding for conversational security analysis.

## Features

- Intent recognition from user queries
- Context extraction for security questions
- Query disambiguation for ambiguous requests
- Natural language interface for AI chat

## AWS Requirements

- **AWS Bedrock**: Claude 3 model access for NLP understanding
- **IAM Permissions**: `bedrock:InvokeModel`

## Setup

1. Enable AWS Bedrock Claude 3 model access
2. Configure AWS credentials
3. Run: `python rose.py chat`

## Usage

```python
from nlp.natural_language_interface import NaturalLanguageInterface

interface = NaturalLanguageInterface()
result = interface.process_query("Show me failed login attempts")
```

## Status

✅ Implemented and tested
🔧 Requires AWS Bedrock configuration to run
