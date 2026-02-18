# Implementation Plan: Fix AWS-Powered Features

## Overview

This implementation plan fixes critical issues preventing the ROSe AI Security Analyst from working for competition screenshots. The approach prioritizes getting the web interface functional first (P0), then fixing command routing (P1), with a focus on demo mode that works without AWS configuration.

## Tasks

- [x] 1. Create demo mode infrastructure
  - [x] 1.1 Create AWS availability detector module
    - Create `src/python/aws_bedrock_athena_ai/api/aws_detector.py`
    - Implement `AWSAvailabilityDetector` class with caching
    - Add methods: `is_bedrock_available()`, `is_athena_available()`, `get_availability_status()`
    - Cache availability checks for 5 minutes to avoid repeated AWS calls
    - _Requirements: US-4.3_
  
  - [x] 1.2 Create demo response generator
    - Create `src/python/aws_bedrock_athena_ai/api/demo_responses.py`
    - Implement `DemoResponseGenerator` class
    - Add `generate_security_response()` method with keyword-based responses
    - Add `get_demo_stats()` method returning realistic numbers
    - Include 3-5 pre-built response templates for common security questions
    - _Requirements: US-1.3, US-1.4_
  
  - [ ]* 1.3 Write property test for graceful degradation
    - **Property 2: Graceful degradation when AWS unavailable**
    - **Validates: Requirements US-2.5, US-3.5, US-4.3**
    - Generate random AWS service failure scenarios
    - Verify system returns valid responses (not 500 errors) for all scenarios
    - Run 100 iterations minimum

- [x] 2. Fix authentication for demo mode
  - [x] 2.1 Add demo mode detection to auth module
    - Modify `src/python/aws_bedrock_athena_ai/api/auth.py`
    - Add `AuthMode` enum (DEMO, PRODUCTION)
    - Add `get_auth_mode()` function that checks AWS availability
    - Implement `optional_auth()` dependency that allows demo access
    - _Requirements: US-1.2, TR-1_
  
  - [x] 2.2 Update API endpoints to use optional authentication
    - Modify `src/python/aws_bedrock_athena_ai/api/main.py`
    - Change `/api/v1/security/question` to use `optional_auth` instead of `require_permission`
    - Change `/api/v1/security/examples` to use `optional_auth`
    - Keep admin endpoints with strict authentication
    - _Requirements: US-1.2_
  
  - [ ]* 2.3 Write property test for demo mode authentication bypass
    - **Property 1: Demo mode allows unauthenticated access**
    - **Validates: Requirements US-1.2**
    - Generate random API requests with/without auth headers
    - Verify no 401 errors in demo mode
    - Run 100 iterations minimum

- [x] 3. Add status endpoint and integrate demo responses
  - [x] 3.1 Create system status endpoint
    - Add `/api/v1/status` endpoint to `api/main.py`
    - Return online status, mode (demo/production), AWS availability
    - Include demo_api_key in response for frontend
    - _Requirements: US-1.1_
  
  - [x] 3.2 Integrate demo response generator into query endpoint
    - Modify `/api/v1/security/question` endpoint
    - Add AWS availability check at start of request
    - If AWS unavailable, call `demo_generator.generate_security_response()`
    - If AWS available, use existing Bedrock logic
    - Ensure response format matches for both paths
    - _Requirements: US-1.3, US-2.4_
  
  - [ ]* 3.3 Write unit tests for status endpoint
    - Test status endpoint returns correct mode in demo
    - Test status endpoint returns correct mode with AWS
    - Test demo response format matches production format
    - _Requirements: US-1.1, US-1.3_

- [x] 4. Checkpoint - Test web interface basics
  - Ensure all tests pass, ask the user if questions arise.
  - Manually verify: Start server, check /api/v1/status returns "online"
  - Manually verify: Web interface loads without errors

- [x] 5. Update frontend for demo mode
  - [x] 5.1 Fix connection status check in frontend
    - Modify `src/python/aws_bedrock_athena_ai/web/static/app.js`
    - Update `checkApiConnection()` to call `/api/v1/status` instead of `/`
    - Update `setConnectionStatus()` to accept mode parameter
    - Display "Connected (Demo)" when in demo mode
    - _Requirements: US-1.1_
  
  - [x] 5.2 Remove strict API key requirement from requests
    - Modify `sendQuestion()` method in app.js
    - Only add Authorization header if apiKey is not 'demo'
    - Allow requests without auth header in demo mode
    - _Requirements: US-1.2_
  
  - [x] 5.3 Update stats display to use demo data
    - Ensure `updateStatsAfterQuery()` works with demo responses
    - Initialize stats with demo values on page load
    - _Requirements: US-1.4_
  
  - [ ]* 5.4 Write unit tests for frontend connection logic
    - Test connection status updates correctly
    - Test requests work without auth header
    - Test stats update after demo query
    - _Requirements: US-1.1, US-1.2, US-1.4_

- [x] 6. Fix cost optimization imports
  - [x] 6.1 Update import statements in demo_cost_optimization.py
    - Modify `src/python/aws_bedrock_athena_ai/demo_cost_optimization.py`
    - Change `from cost_optimization import ...` to `from aws_bedrock_athena_ai.cost_optimization.cost_optimizer import CostOptimizer`
    - Update all cost_optimization imports to use full package path
    - _Requirements: US-3.1, TR-5_
  
  - [x] 6.2 Add mock mode for cost optimization when AWS unavailable
    - Add AWS Cost Explorer availability check
    - Return mock cost data if Cost Explorer not configured
    - Ensure demo still shows dashboard, metrics, and Free Tier status
    - _Requirements: US-3.2, US-3.3, US-3.4, US-3.5_
  
  - [ ]* 6.3 Write unit test for cost demo imports
    - Test module imports without ImportError
    - Test demo runs with mock data when AWS unavailable
    - _Requirements: US-3.1, US-3.5_

- [x] 7. Verify and test chat command routing
  - [x] 7.1 Verify chat command exists in rose.py
    - Check `rose.py` has 'chat' in command list
    - Verify routing to `aws_bedrock_athena_ai.cli`
    - Add graceful error handling if CLI module unavailable
    - _Requirements: US-2.1, US-2.2_
  
  - [x] 7.2 Add demo mode support to CLI chat interface
    - Modify `src/python/aws_bedrock_athena_ai/cli.py`
    - Add AWS availability check on startup
    - Display "Demo Mode" message if AWS unavailable
    - Allow chat to work with demo responses
    - _Requirements: US-2.3, US-2.4, US-2.5_
  
  - [ ]* 7.3 Write property test for command routing
    - **Property 5: Command routing recognizes all documented commands**
    - **Validates: Requirements US-2.1**
    - Extract all documented commands from help text
    - Verify each command routes without "invalid choice" error
    - Run 100 iterations minimum

- [x] 8. Add clear error messages and instructions
  - [x] 8.1 Create error message templates
    - Add clear message for "AWS Bedrock not configured"
    - Add clear message for "Athena not set up"
    - Include setup instructions in error messages
    - _Requirements: US-4.1, US-4.2, US-4.4_
  
  - [x] 8.2 Update exception handlers to use templates
    - Modify error handlers in `api/main.py`
    - Modify error handlers in `cli.py`
    - Ensure errors are logged but don't crash the application
    - _Requirements: US-4.1, US-4.2_
  
  - [ ]* 8.3 Write unit tests for error messages
    - Test Bedrock unavailable shows correct message
    - Test Athena unavailable shows correct message
    - Test messages include setup instructions
    - _Requirements: US-4.1, US-4.2, US-4.4_

- [ ] 9. Final checkpoint and integration testing
  - Ensure all tests pass, ask the user if questions arise.
  - Run full integration test: web interface end-to-end
  - Verify all P0 requirements met for screenshots

- [ ] 10. Create screenshot validation checklist
  - [ ] 10.1 Document screenshot requirements
    - Create checklist of all features to screenshot
    - Document how to start each feature
    - Include expected output for each screenshot
    - _Requirements: Success Criteria_
  
  - [ ] 10.2 Test screenshot workflow
    - Start web interface: `python rose.py demo web`
    - Verify "Connected (Demo)" status
    - Submit query: "What are our top security risks?"
    - Verify response appears
    - Verify quick stats show: queries > 0, response time > 0, threats > 0
    - Click example question and verify it works
    - Test chat command: `python rose.py chat`
    - Test cost demo: `python rose.py demo cost`
    - _Requirements: Success Criteria_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Focus on P0 tasks first (web interface) for competition screenshots
- Demo mode is acceptable for competition - full AWS integration can come later
- All property tests should run minimum 100 iterations
- Each property test must reference its design document property
- Unit tests focus on specific examples and edge cases
- Property tests verify universal behavior across all inputs

## Testing Configuration

**Property-Based Testing Library**: Use `hypothesis` for Python

**Minimum Iterations**: 100 per property test

**Test Tags**: Each property test must include a comment:
```python
# Feature: fix-aws-features, Property N: [property text]
```

## Priority Breakdown

**P0 (Must Fix for Screenshots)**:
- Tasks 1-6: Web interface, authentication, demo mode, frontend
- Estimated time: 2-3 hours

**P1 (Should Fix)**:
- Tasks 7-8: Chat command, cost optimization, error messages
- Estimated time: 1-1.5 hours

**P2 (Nice to Have)**:
- Task 10: Screenshot validation and documentation
- Estimated time: 30 minutes

**Total Estimated Time**: 3.5-5 hours

---

**Plan Version**: 1.0  
**Created**: 2026-02-18  
**Status**: Ready for Execution
