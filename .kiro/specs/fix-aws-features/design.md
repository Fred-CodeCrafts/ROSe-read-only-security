# Fix AWS-Powered Features - Design Document

## Overview

This design addresses critical issues preventing the ROSe AI Security Analyst web interface and CLI features from functioning correctly. The primary problems are:

1. **Authentication Issues**: Web interface returns 401 errors due to strict API key validation
2. **Connection Status**: WebSocket/connection status shows "Disconnected" 
3. **Command Routing**: `chat` command not recognized in rose.py
4. **Import Errors**: Cost optimization demo has incorrect import paths
5. **Missing Demo Mode**: No fallback when AWS Bedrock is unavailable

The solution implements a **demo-first approach** where features work immediately for screenshots and testing, with graceful degradation when AWS services aren't configured.

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Interface                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Connection   │  │ Query Input  │  │ Quick Stats  │      │
│  │ Status       │  │              │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Authentication Middleware                           │   │
│  │  • Demo mode: Allow unauthenticated access          │   │
│  │  • Production mode: Validate API keys               │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Query Processing Layer                              │   │
│  │  • Detect AWS availability                           │   │
│  │  • Route to AWS Bedrock OR Demo responder           │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   AWS Bedrock            │  │   Demo Mode              │
│   (if configured)        │  │   (fallback)             │
│                          │  │                          │
│  • Real AI responses     │  │  • Mock responses        │
│  • Athena queries        │  │  • Simulated data        │
│  • Cost tracking         │  │  • No AWS required       │
└──────────────────────────┘  └──────────────────────────┘
```

### Component Interaction

1. **Frontend (app.js)**:
   - Removes strict API key requirement for demo mode
   - Auto-detects connection status
   - Handles both authenticated and demo modes

2. **Backend (api/main.py)**:
   - Modified authentication middleware to allow demo access
   - AWS availability detection
   - Automatic fallback to demo responses

3. **CLI Router (rose.py)**:
   - Adds `chat` command routing
   - Fixes import paths for cost optimization
   - Provides clear error messages

4. **Demo Mode Handler**:
   - Detects when AWS services unavailable
   - Returns realistic mock responses
   - Maintains same API contract

## Components and Interfaces

### 1. Authentication Middleware Enhancement

**Location**: `src/python/aws_bedrock_athena_ai/api/auth.py`

**Current Issue**: Strict API key validation returns 401 for all requests

**Solution**: Add demo mode detection

```python
class AuthMode(Enum):
    DEMO = "demo"
    PRODUCTION = "production"

def get_auth_mode() -> AuthMode:
    """Detect if running in demo or production mode"""
    # Check for AWS credentials
    # Check for DEMO_MODE environment variable
    # Return appropriate mode

async def optional_auth(request: Request) -> Dict:
    """
    Optional authentication for demo mode.
    Returns user data if authenticated, demo user if not.
    """
    auth_mode = get_auth_mode()
    
    if auth_mode == AuthMode.DEMO:
        return {
            "user_id": "demo_user",
            "permissions": ["query", "read"],
            "mode": "demo"
        }
    
    # Production mode - require authentication
    return await get_current_user(request)
```

**Interface**:
- Input: HTTP Request
- Output: User data dict with mode indicator
- Side effects: None

### 2. Demo Response Generator

**Location**: `src/python/aws_bedrock_athena_ai/api/demo_responses.py` (new file)

**Purpose**: Generate realistic mock responses when AWS unavailable

```python
class DemoResponseGenerator:
    """Generates realistic demo responses for security queries"""
    
    def generate_security_response(
        self, 
        question: str,
        conversation_id: str
    ) -> SecurityQuestionResponse:
        """
        Generate a demo response based on question keywords.
        Returns realistic-looking analysis without AWS calls.
        """
        pass
    
    def get_demo_stats(self) -> Dict:
        """Return demo statistics for quick stats display"""
        return {
            "queries_today": 12,
            "avg_response_time": 245,
            "threats_detected": 3
        }
```

**Interface**:
- Input: Security question string, conversation ID
- Output: SecurityQuestionResponse object
- Side effects: None (pure function)

### 3. AWS Availability Detector

**Location**: `src/python/aws_bedrock_athena_ai/api/aws_detector.py` (new file)

**Purpose**: Detect if AWS services are configured and available

```python
class AWSAvailabilityDetector:
    """Detects AWS service availability"""
    
    def __init__(self):
        self._bedrock_available = None
        self._athena_available = None
        self._last_check = None
    
    def is_bedrock_available(self) -> bool:
        """Check if AWS Bedrock is configured and accessible"""
        # Check for credentials
        # Try to list models (lightweight check)
        # Cache result for 5 minutes
        pass
    
    def is_athena_available(self) -> bool:
        """Check if Athena is configured"""
        # Check for database/table configuration
        # Cache result
        pass
    
    def get_availability_status(self) -> Dict:
        """Get comprehensive availability status"""
        return {
            "bedrock": self.is_bedrock_available(),
            "athena": self.is_athena_available(),
            "mode": "production" if self.is_bedrock_available() else "demo"
        }
```

**Interface**:
- Input: None (checks environment/AWS)
- Output: Boolean or status dict
- Side effects: AWS API calls (cached)

### 4. Modified API Endpoints

**Location**: `src/python/aws_bedrock_athena_ai/api/main.py`

**Changes**:

```python
# Add demo response generator
demo_generator = DemoResponseGenerator()
aws_detector = AWSAvailabilityDetector()

@app.get("/api/v1/status")
async def get_status():
    """Return system status including AWS availability"""
    availability = aws_detector.get_availability_status()
    return {
        "status": "online",
        "mode": availability["mode"],
        "aws_bedrock": availability["bedrock"],
        "aws_athena": availability["athena"],
        "demo_mode": not availability["bedrock"]
    }

@app.post("/api/v1/security/question")
async def ask_security_question(
    request: SecurityQuestionRequest,
    user_data: Dict = Depends(optional_auth)  # Changed from require_permission
):
    """Process security question with demo fallback"""
    
    # Check if AWS available
    if not aws_detector.is_bedrock_available():
        # Return demo response
        return demo_generator.generate_security_response(
            request.question,
            request.conversation_id or str(uuid.uuid4())
        )
    
    # Original AWS Bedrock logic
    # ...
```

### 5. Frontend Connection Status

**Location**: `src/python/aws_bedrock_athena_ai/web/static/app.js`

**Changes**:

```javascript
async checkApiConnection() {
    try {
        // Call new status endpoint
        const response = await fetch('/api/v1/status');
        const data = await response.json();
        
        if (response.ok && data.status === 'online') {
            this.apiKey = data.demo_api_key || 'demo';
            this.setConnectionStatus(true, data.mode);
        } else {
            this.setConnectionStatus(false);
        }
    } catch (error) {
        console.error('API connection failed:', error);
        this.setConnectionStatus(false);
    }
}

setConnectionStatus(online, mode = 'unknown') {
    const statusDot = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');
    
    if (online) {
        statusDot.className = 'status-dot online';
        statusText.textContent = mode === 'demo' ? 'Connected (Demo)' : 'Connected';
    } else {
        statusDot.className = 'status-dot offline';
        statusText.textContent = 'Disconnected';
    }
}

async sendQuestion() {
    // Remove strict API key check
    // Allow requests without Authorization header in demo mode
    const headers = {
        'Content-Type': 'application/json'
    };
    
    // Only add auth header if we have a real API key
    if (this.apiKey && this.apiKey !== 'demo') {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    
    const response = await fetch('/api/v1/security/question', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({...})
    });
}
```

### 6. CLI Command Routing Fix

**Location**: `rose.py`

**Changes**:

```python
# Add chat command routing (already exists in current code)
# Fix cost optimization import

elif command == 'demo':
    if len(sys.argv) > 2:
        demo_type = sys.argv[2].lower()
        
        if demo_type == 'cost':
            print("💰 Running Cost Optimization Demo...")
            try:
                # Fix import path
                from aws_bedrock_athena_ai.demo_cost_optimization import main as cost_main
                return cost_main()
            except ImportError as e:
                print(f"❌ Error: {e}")
                print("💡 Make sure cost_optimization module is installed")
                return 1
```

### 7. Cost Optimization Import Fix

**Location**: `src/python/aws_bedrock_athena_ai/demo_cost_optimization.py`

**Current Issue**: `from cost_optimization import ...` (missing package prefix)

**Solution**: Add proper package prefix

```python
# Change from:
from cost_optimization import CostOptimizer, ModelSelector, CacheManager
from cost_optimization.models import ModelSelectionCriteria, ServiceType
from cost_optimization.throttling_manager import RequestPriority

# To:
from aws_bedrock_athena_ai.cost_optimization.cost_optimizer import CostOptimizer
from aws_bedrock_athena_ai.cost_optimization.model_selector import ModelSelector
from aws_bedrock_athena_ai.cost_optimization.cache_manager import CacheManager
from aws_bedrock_athena_ai.cost_optimization.models import (
    ModelSelectionCriteria, ServiceType
)
from aws_bedrock_athena_ai.cost_optimization.throttling_manager import RequestPriority
```

## Data Models

### AuthMode Enum

```python
class AuthMode(Enum):
    """Authentication mode for the API"""
    DEMO = "demo"          # No authentication required
    PRODUCTION = "production"  # API key required
```

### AWSAvailabilityStatus

```python
@dataclass
class AWSAvailabilityStatus:
    """AWS service availability status"""
    bedrock_available: bool
    athena_available: bool
    mode: AuthMode
    last_checked: datetime
    error_message: Optional[str] = None
```

### DemoResponse

```python
@dataclass
class DemoResponse:
    """Demo mode response structure"""
    question: str
    conversation_id: str
    response_type: str  # "threat_analysis", "query_result", etc.
    mock_data: Dict[str, Any]
    timestamp: datetime
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Demo mode allows unauthenticated access
*For any* API request in demo mode, the request should succeed without requiring an API key or authentication header.
**Validates: Requirements US-1.2**

### Property 2: Graceful degradation when AWS unavailable
*For any* AWS service (Bedrock, Athena), when the service is unavailable or not configured, the system should fall back to demo mode and return mock responses instead of errors.
**Validates: Requirements US-2.5, US-3.5, US-4.3**

### Property 3: Connection status reflects actual availability
*For any* system state, the connection status indicator should accurately reflect whether the API is reachable and responding.
**Validates: Requirements US-1.1**

### Property 4: Import paths resolve correctly
*For any* module import in the cost optimization demo, the import should resolve to the correct module without ImportError.
**Validates: Requirements US-3.1**

### Property 5: Command routing recognizes all documented commands
*For any* documented command in rose.py (chat, demo, aws, etc.), the command should be recognized and routed to the correct handler without "invalid choice" errors.
**Validates: Requirements US-2.1**

## Error Handling

### Error Categories

1. **AWS Service Unavailable**
   - Detection: Boto3 client errors, credential errors
   - Response: Log warning, switch to demo mode
   - User message: "Running in demo mode - AWS Bedrock not configured"

2. **Import Errors**
   - Detection: ImportError exceptions
   - Response: Log error with module name
   - User message: "Module not found: {module}. Please check installation."

3. **Authentication Errors (Production Mode)**
   - Detection: Missing/invalid API key
   - Response: Return 401 with clear message
   - User message: "API key required. Get your key from /api"

4. **Connection Errors**
   - Detection: Network timeouts, connection refused
   - Response: Retry with exponential backoff (3 attempts)
   - User message: "Connection failed. Retrying..."

### Error Response Format

```python
@dataclass
class ErrorResponse:
    """Standard error response"""
    error_code: str
    error_message: str
    details: Dict[str, Any]
    recovery_suggestion: str
    timestamp: datetime
```

### Graceful Degradation Strategy

```
AWS Service Check
    │
    ├─ Available ──> Use AWS Bedrock
    │
    └─ Unavailable ──> Demo Mode
                        │
                        ├─ Log: "AWS not configured, using demo mode"
                        ├─ Return: Mock responses
                        └─ Display: "Demo Mode" indicator
```

## Testing Strategy

### Dual Testing Approach

This feature requires both **unit tests** for specific scenarios and **property tests** for general behavior:

- **Unit tests**: Verify specific examples (demo mode activation, specific error messages, import fixes)
- **Property tests**: Verify universal properties (graceful degradation for all AWS services, authentication bypass in demo mode)

Both approaches are complementary and necessary for comprehensive coverage.

### Unit Tests

**Test File**: `tests/test_fix_aws_features.py`

1. **test_demo_mode_allows_unauthenticated_access**
   - Setup: Start API in demo mode
   - Action: Send request without API key
   - Assert: Response is 200, not 401

2. **test_connection_status_shows_connected_in_demo_mode**
   - Setup: Start API in demo mode
   - Action: Call /api/v1/status
   - Assert: status="online", mode="demo"

3. **test_query_returns_demo_response_when_bedrock_unavailable**
   - Setup: Mock AWS Bedrock as unavailable
   - Action: Submit security question
   - Assert: Response contains mock data, no AWS errors

4. **test_chat_command_recognized**
   - Setup: None
   - Action: Run `python rose.py chat` (capture sys.argv)
   - Assert: No "invalid choice" error

5. **test_cost_demo_imports_correctly**
   - Setup: None
   - Action: Import demo_cost_optimization module
   - Assert: No ImportError

6. **test_quick_stats_show_nonzero_values**
   - Setup: Process one demo query
   - Action: Get stats from demo generator
   - Assert: queries_today > 0, avg_response_time > 0

7. **test_error_message_when_bedrock_not_configured**
   - Setup: Remove AWS credentials
   - Action: Attempt to use Bedrock
   - Assert: Error message contains "AWS Bedrock not configured"

8. **test_example_questions_load_in_demo_mode**
   - Setup: Start API in demo mode
   - Action: Call /api/v1/security/examples
   - Assert: Returns list of example questions

### Property-Based Tests

**Test File**: `tests/test_fix_aws_features_properties.py`

**Configuration**: Minimum 100 iterations per property test

1. **Property Test: Graceful degradation for all AWS services**
   - **Tag**: Feature: fix-aws-features, Property 2: Graceful degradation when AWS unavailable
   - **Generator**: Generate random AWS service failure scenarios (Bedrock down, Athena down, both down)
   - **Property**: For any AWS service failure, system returns valid response (not 500 error)
   - **Validates**: Requirements US-2.5, US-3.5, US-4.3

2. **Property Test: Demo mode authentication bypass**
   - **Tag**: Feature: fix-aws-features, Property 1: Demo mode allows unauthenticated access
   - **Generator**: Generate random API requests with/without auth headers
   - **Property**: For any request in demo mode, response is not 401
   - **Validates**: Requirements US-1.2

3. **Property Test: Command routing completeness**
   - **Tag**: Feature: fix-aws-features, Property 5: Command routing recognizes all documented commands
   - **Generator**: Generate all documented commands from help text
   - **Property**: For any documented command, no "invalid choice" error
   - **Validates**: Requirements US-2.1

### Integration Tests

**Test File**: `tests/test_fix_aws_features_integration.py`

1. **test_end_to_end_demo_workflow**
   - Start web server in demo mode
   - Load web interface
   - Submit query
   - Verify response and stats update

2. **test_aws_to_demo_fallback**
   - Start with AWS configured
   - Simulate AWS failure mid-request
   - Verify fallback to demo mode

### Manual Testing Checklist (For Screenshots)

- [ ] Web interface loads at http://localhost:8000
- [ ] Connection status shows "Connected (Demo)"
- [ ] Submit query: "What are our top security risks?"
- [ ] Response appears in chat
- [ ] Quick stats show non-zero numbers
- [ ] Click example question
- [ ] Example question submits and gets response
- [ ] Run `python rose.py chat` - no error
- [ ] Run `python rose.py demo cost` - shows output
- [ ] Take screenshots of all working features

## Implementation Notes

### Priority Order

1. **P0 - Web Interface** (Critical for screenshots)
   - Fix authentication middleware
   - Add demo response generator
   - Update frontend connection check
   - Test: Web interface shows "Connected" and processes queries

2. **P1 - Command Routing**
   - Already fixed in current rose.py (verify)
   - Fix cost optimization imports
   - Test: Commands run without errors

3. **P2 - Polish**
   - Add better error messages
   - Add demo mode indicator in UI
   - Add AWS setup instructions

### Configuration

**Environment Variables**:
- `DEMO_MODE=true` - Force demo mode even if AWS configured
- `AWS_REGION` - AWS region for services
- `BEDROCK_MODEL_ID` - Model to use (if AWS configured)

**Demo Mode Detection Logic**:
```python
def is_demo_mode() -> bool:
    # Explicit demo mode flag
    if os.getenv('DEMO_MODE', '').lower() == 'true':
        return True
    
    # Check for AWS credentials
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        if not credentials:
            return True
    except Exception:
        return True
    
    # Check if Bedrock accessible
    try:
        bedrock = boto3.client('bedrock-runtime')
        bedrock.list_foundation_models()
        return False  # AWS works, not demo mode
    except Exception:
        return True  # AWS not accessible, use demo mode
```

### Performance Considerations

- Cache AWS availability checks (5 minute TTL)
- Demo responses should be instant (<50ms)
- Don't retry AWS calls in demo mode
- Lazy-load AWS clients only when needed

### Security Considerations

- Demo mode should be clearly indicated in UI
- Don't expose real data in demo mode
- Production mode still requires authentication
- Log all demo mode activations

## Dependencies

- **Existing**: FastAPI, boto3, uvicorn
- **New**: None (uses existing dependencies)

## Deployment

### Local Development
```bash
# Set demo mode
export DEMO_MODE=true

# Start web interface
python rose.py demo web

# Access at http://localhost:8000
```

### Production (with AWS)
```bash
# Configure AWS credentials
aws configure

# Start without demo mode flag
python rose.py demo web
```

## Success Metrics

### For Competition Screenshots
- ✅ Web interface shows "Connected"
- ✅ At least one query processes successfully
- ✅ Quick stats show: 12 queries, 245ms avg, 3 threats
- ✅ Example questions clickable and work
- ✅ `python rose.py chat` starts without error
- ✅ `python rose.py demo cost` runs and shows output

### For Production
- ✅ All features work with AWS configured
- ✅ Graceful fallback when AWS unavailable
- ✅ Clear error messages guide users
- ✅ Demo mode works for testing

## Future Enhancements

1. **Persistent Demo Data**: Save demo queries/responses to simulate history
2. **Demo Mode Tutorial**: Interactive guide for new users
3. **AWS Setup Wizard**: CLI tool to configure AWS services
4. **Hybrid Mode**: Use AWS when available, demo for specific features
5. **Demo Mode Analytics**: Track which features users try in demo mode

---

**Document Version**: 1.0  
**Last Updated**: 2026-02-18  
**Status**: Ready for Implementation
