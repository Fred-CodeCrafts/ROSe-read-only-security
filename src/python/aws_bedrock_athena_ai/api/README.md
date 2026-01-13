# AI Security Analyst API

REST API for natural language security analysis using AWS Bedrock and Athena.

## Features

- **Natural Language Processing**: Ask security questions in plain English
- **Authentication & Rate Limiting**: API key-based authentication with rate limiting
- **Multi-turn Conversations**: Support for clarification and follow-up questions
- **Comprehensive Analysis**: Executive summaries, technical details, and recommendations
- **Web Interface**: Interactive chat-like interface for demonstrations

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the API Server

```bash
# Start with web interface
python demo_web_interface.py

# Or start API only
python run_api.py
```

### 3. Access the Interface

- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### Authentication

All API endpoints require authentication using an API key in the Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

A demo API key is automatically generated and displayed when you start the server.

### Core Endpoints

#### `POST /api/v1/security/question`

Process a natural language security question.

**Request:**
```json
{
    "question": "Are we being attacked right now?",
    "conversation_id": "optional-conversation-id",
    "user_role": "analyst"
}
```

**Response:**
```json
{
    "success": true,
    "conversation_id": "uuid-string",
    "needs_clarification": false,
    "executive_summary": "Analysis summary...",
    "technical_details": {
        "threats_found": 3,
        "risk_score": 7.5
    },
    "recommendations": [...],
    "visualizations": [...],
    "action_plan": {...},
    "processing_time_ms": 1250.5,
    "confidence_score": 0.85
}
```

#### `POST /api/v1/security/clarification`

Handle clarification responses for ambiguous questions.

**Request:**
```json
{
    "original_question": "Show me threats",
    "clarification_response": "Threats from the last 24 hours",
    "conversation_id": "uuid-string"
}
```

#### `GET /api/v1/security/examples`

Get example security questions and supported intents.

**Response:**
```json
{
    "examples": [
        "Are we being attacked right now?",
        "Show me security threats from last week",
        ...
    ],
    "supported_intents": [
        "threat_hunting",
        "compliance_check",
        ...
    ]
}
```

### Utility Endpoints

#### `GET /health`

Health check endpoint.

#### `GET /api/v1/auth/rate-limit`

Get current rate limit information.

#### `POST /api/v1/auth/api-key`

Create a new API key (admin permission required).

## Web Interface

The web interface provides a chat-like experience for interacting with the AI Security Analyst:

### Features

- **Interactive Chat**: Ask questions and receive responses in real-time
- **Example Questions**: Click on example questions to get started quickly
- **Detailed Results**: View executive summaries, technical details, recommendations, and visualizations
- **API Access**: Copy the demo API key for programmatic access
- **Real-time Stats**: Track queries, response times, and threats detected

### Usage

1. Open http://localhost:8000 in your browser
2. Type a security question in the chat input
3. Press Enter or click the send button
4. View the response and click "View Details" for comprehensive analysis

## Example Questions

Try these example questions to see the system in action:

- "Are we being attacked right now?"
- "Show me security threats from last week"
- "What are our biggest security risks?"
- "Check for compliance violations on web servers"
- "Investigate the security incident from yesterday"
- "Find suspicious login attempts from the past 24 hours"
- "Analyze malware activity on endpoints"
- "Review user access permissions"

## Rate Limits

- **Default Limit**: 100 requests per hour per API key
- **Rate Limit Headers**: Responses include rate limit information
- **429 Status**: Returned when rate limit is exceeded

## Error Handling

The API returns structured error responses:

```json
{
    "success": false,
    "error_code": "INVALID_REQUEST",
    "error_message": "Human-readable error message",
    "details": {...},
    "timestamp": "2024-01-13T10:30:00Z"
}
```

## Development

### Testing

```bash
# Test basic API functionality
python test_api_basic.py

# Run full test suite
pytest tests/
```

### Configuration

Environment variables:

- `API_HOST`: Server host (default: 0.0.0.0)
- `API_PORT`: Server port (default: 8000)
- `API_RELOAD`: Enable auto-reload (default: true)

## Security Notes

- The demo uses in-memory storage for API keys and rate limits
- In production, use a proper database and secure key management
- Implement proper logging and monitoring
- Use HTTPS in production environments
- Validate and sanitize all inputs

## Integration

### Python Client Example

```python
import requests

api_key = "your-api-key"
base_url = "http://localhost:8000"

headers = {"Authorization": f"Bearer {api_key}"}

response = requests.post(
    f"{base_url}/api/v1/security/question",
    headers=headers,
    json={"question": "Are we being attacked?"}
)

data = response.json()
print(data["executive_summary"])
```

### JavaScript Client Example

```javascript
const apiKey = "your-api-key";
const baseUrl = "http://localhost:8000";

const response = await fetch(`${baseUrl}/api/v1/security/question`, {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        question: "Are we being attacked?"
    })
});

const data = await response.json();
console.log(data.executive_summary);
```

## Architecture

The API is built using:

- **FastAPI**: Modern, fast web framework for building APIs
- **Pydantic**: Data validation and serialization
- **Uvicorn**: ASGI server for production deployment
- **AWS SDK**: Integration with Bedrock and Athena services

## Next Steps

1. Configure AWS credentials for full functionality
2. Set up proper data sources in S3
3. Customize the analysis logic for your environment
4. Deploy to production with proper security measures
5. Implement monitoring and logging