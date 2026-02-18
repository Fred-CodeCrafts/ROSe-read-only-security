# Fix AWS-Powered Features - Requirements

## Problem Statement

The ROSe AI Security Analyst has several AWS-powered features that are not working correctly:

1. **Web Interface Issues:**
   - Shows "Disconnected" status
   - API returns 401 Unauthorized errors
   - Queries fail with "Error: An error occurred processing your request"
   - Quick stats show all zeros (0 queries, 0ms response, 0 threats)

2. **Chat Command Not Working:**
   - `python rose.py chat` fails with "invalid choice: 'chat'"
   - Command routing is broken in rose.py

3. **Cost Optimization Demo Broken:**
   - `python rose.py demo cost` fails with "No module named 'cost_optimization'"
   - Import path issue

4. **Authentication Issues:**
   - Web interface requires API key but demo key doesn't work
   - 401 Unauthorized on all API endpoints

## Current State

### What's Working ✅
- CloudWatch dashboard with metrics
- Athena queries with 90 security events
- Web server starts and runs
- Insights demo works perfectly
- Onboarding demo works perfectly

### What's Broken ❌
- Web interface API calls (401 errors)
- Chat command routing
- Cost optimization imports
- WebSocket connection (shows "Disconnected")
- Query processing returns errors

## User Stories

### US-1: Working Web Interface
**As a** security analyst  
**I want** the web interface to connect and process queries  
**So that** I can interact with my security data through a browser

**Acceptance Criteria:**
- [ ] Web interface shows "Connected" status (not "Disconnected")
- [ ] API authentication works with demo key
- [ ] Security queries return actual results (not errors)
- [ ] Quick stats show real numbers (queries, response time, threats)
- [ ] Example questions work when clicked
- [ ] Chat input accepts and processes queries

### US-2: Working Chat Command
**As a** developer  
**I want** `python rose.py chat` to work  
**So that** I can use the CLI chat interface

**Acceptance Criteria:**
- [ ] `python rose.py chat` command is recognized
- [ ] Chat interface starts successfully
- [ ] Can ask security questions
- [ ] Receives responses from AI
- [ ] Works with or without AWS Bedrock (graceful degradation)

### US-3: Working Cost Optimization
**As a** user  
**I want** the cost optimization demo to run  
**So that** I can see AWS cost tracking features

**Acceptance Criteria:**
- [ ] `python rose.py demo cost` runs without import errors
- [ ] Shows cost optimization dashboard
- [ ] Displays usage metrics
- [ ] Shows Free Tier status
- [ ] Works with mock data if AWS Cost Explorer not configured

### US-4: Proper Error Handling
**As a** user  
**I want** clear error messages when AWS services aren't configured  
**So that** I understand what's needed

**Acceptance Criteria:**
- [ ] Clear message when AWS Bedrock not configured
- [ ] Clear message when Athena not set up
- [ ] Graceful degradation to demo mode
- [ ] Helpful instructions for AWS setup

## Technical Requirements

### TR-1: Fix Web Interface Authentication
- Remove or fix API key requirement for demo mode
- Allow unauthenticated access for demo
- Or auto-inject demo API key in frontend

### TR-2: Fix WebSocket Connection
- Ensure WebSocket endpoint is accessible
- Handle connection errors gracefully
- Show proper connection status

### TR-3: Fix API Endpoints
- `/api/v1/security/question` should process queries
- `/api/v1/security/examples` should return examples
- Handle Bedrock unavailability gracefully
- Return mock responses if AWS not configured

### TR-4: Fix rose.py Command Routing
- Add 'chat' command to rose.py
- Route to correct CLI module
- Handle missing dependencies

### TR-5: Fix Cost Optimization Imports
- Fix import path in demo_cost_optimization.py
- Ensure all dependencies are available
- Add mock mode if AWS Cost Explorer not available

### TR-6: Add Demo Mode
- Detect when AWS services aren't available
- Fall back to mock/demo responses
- Still show functionality for screenshots

## Success Criteria

### For Competition Screenshots:
1. Web interface shows "Connected" and processes at least one query successfully
2. Quick stats show non-zero numbers
3. At least one example question returns a response
4. Chat command starts (even if shows "AWS Bedrock required" message)
5. Cost demo shows something (even if mock data)

### For Production:
1. All features work with proper AWS configuration
2. Graceful degradation when AWS not configured
3. Clear error messages guide users to setup
4. Demo mode works for testing/screenshots

## Out of Scope

- Full AWS Bedrock integration (already implemented, just needs configuration)
- Advanced cost optimization features
- Production-grade authentication
- Multi-user support

## Dependencies

- AWS credentials configured (already done)
- S3 buckets created (already done)
- Athena table created (already done)
- CloudWatch metrics published (already done)
- AWS Bedrock access (optional - should work without)

## Priority

**P0 (Must Fix for Screenshots):**
- Web interface connection status
- At least one working query in web interface
- Quick stats showing numbers

**P1 (Should Fix):**
- Chat command routing
- Cost optimization imports
- Better error messages

**P2 (Nice to Have):**
- Full demo mode with mock responses
- Comprehensive error handling
- Setup validation script

## Notes

- Focus on making features work for screenshots first
- Full AWS integration can be completed later
- Demo mode is acceptable for competition
- Clear documentation of what requires AWS vs what works standalone

## Related Files

- `src/python/aws_bedrock_athena_ai/demo_web_interface.py` - Web server
- `src/python/aws_bedrock_athena_ai/web/static/app.js` - Frontend
- `src/python/aws_bedrock_athena_ai/api/main.py` - API endpoints
- `rose.py` - CLI routing
- `src/python/aws_bedrock_athena_ai/demo_cost_optimization.py` - Cost demo

## Timeline

- **Phase 1 (1-2 hours):** Fix web interface authentication and connection
- **Phase 2 (30 min):** Fix chat command routing
- **Phase 3 (30 min):** Fix cost optimization imports
- **Phase 4 (30 min):** Add demo mode fallbacks
- **Total:** 2.5-3.5 hours

## Definition of Done

- [ ] Web interface shows "Connected"
- [ ] At least one query works in web interface
- [ ] Quick stats show non-zero numbers
- [ ] `python rose.py chat` command recognized
- [ ] `python rose.py demo cost` runs without errors
- [ ] Screenshots can be taken of all features
- [ ] README updated with current status
- [ ] Demo mode documented

---

**Created:** 2026-02-18  
**Status:** Ready for Implementation  
**Priority:** P0 - Critical for Competition
