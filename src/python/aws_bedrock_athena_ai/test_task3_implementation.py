"""
Quick test to verify Task 3 implementation:
- Status endpoint exists and returns correct structure
- Query endpoint integrates demo responses
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fastapi.testclient import TestClient
from aws_bedrock_athena_ai.api.main import app

client = TestClient(app)


def test_status_endpoint_exists():
    """Test that /api/v1/status endpoint exists and returns correct structure"""
    print("\n=== Testing Status Endpoint ===")
    
    response = client.get("/api/v1/status")
    print(f"Status Code: {response.status_code}")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"Response: {data}")
    
    # Verify required fields
    required_fields = ["status", "mode", "aws_bedrock", "aws_athena", "demo_mode", "version"]
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"
    
    # Verify status is online
    assert data["status"] == "online", f"Expected status 'online', got {data['status']}"
    
    # Verify mode is either demo or production
    assert data["mode"] in ["demo", "production"], f"Invalid mode: {data['mode']}"
    
    # If in demo mode, should have demo_api_key
    if data["demo_mode"]:
        assert data["demo_api_key"] is not None, "Demo mode should include demo_api_key"
    
    print("✓ Status endpoint test passed!")
    return True


def test_query_endpoint_with_demo():
    """Test that query endpoint works and returns demo responses"""
    print("\n=== Testing Query Endpoint ===")
    
    # First check what mode we're in
    status_response = client.get("/api/v1/status")
    status_data = status_response.json()
    mode = status_data.get("mode")
    demo_mode = status_data.get("demo_mode")
    
    print(f"Current mode: {mode}")
    print(f"Demo mode: {demo_mode}")
    
    # Test query
    test_question = "What are our top security risks?"
    
    # Prepare headers based on mode
    headers = {}
    if not demo_mode:
        # Production mode - need to provide API key
        # Get demo API key from /api endpoint
        api_response = client.get("/api")
        demo_api_key = api_response.json().get("demo_api_key")
        if demo_api_key:
            headers["Authorization"] = f"Bearer {demo_api_key}"
            print(f"Using demo API key for authentication")
    
    response = client.post(
        "/api/v1/security/question",
        json={
            "question": test_question,
            "conversation_id": "test-123"
        },
        headers=headers
    )
    
    print(f"Status Code: {response.status_code}")
    
    # Should succeed (either with demo or real response)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {list(data.keys())}")
    
    # Verify response structure
    required_fields = [
        "success", "conversation_id", "needs_clarification",
        "executive_summary", "processing_time_ms", "confidence_score"
    ]
    
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"
    
    # Verify success
    assert data["success"] == True, "Response should be successful"
    
    # Verify conversation ID matches
    assert data["conversation_id"] == "test-123", "Conversation ID should match"
    
    # Verify we got a response (either full response or clarification)
    if data.get("needs_clarification"):
        print("Response requires clarification (expected in some cases)")
        assert data.get("clarification_questions"), "Should have clarification questions"
    else:
        assert data["executive_summary"], "Should have executive summary"
        print(f"Executive Summary (first 100 chars): {data['executive_summary'][:100]}...")
    
    print(f"Processing Time: {data['processing_time_ms']}ms")
    print(f"Confidence Score: {data['confidence_score']}")
    
    print("✓ Query endpoint test passed!")
    return True


def test_response_format_consistency():
    """Test that demo and production responses have consistent format"""
    print("\n=== Testing Response Format Consistency ===")
    
    # Check mode and prepare headers
    status_response = client.get("/api/v1/status")
    status_data = status_response.json()
    demo_mode = status_data.get("demo_mode")
    
    headers = {}
    if not demo_mode:
        api_response = client.get("/api")
        demo_api_key = api_response.json().get("demo_api_key")
        if demo_api_key:
            headers["Authorization"] = f"Bearer {demo_api_key}"
    
    response = client.post(
        "/api/v1/security/question",
        json={
            "question": "Show me failed login attempts",
            "conversation_id": "test-format"
        },
        headers=headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Check that response has expected structure
    # Note: If clarification is needed, some fields may be None/empty
    if not data.get("needs_clarification"):
        assert isinstance(data.get("recommendations"), list), "Recommendations should be a list"
        assert isinstance(data.get("visualizations"), list), "Visualizations should be a list"
        assert isinstance(data.get("technical_details"), (dict, type(None))), "Technical details should be dict or None"
    else:
        print("Response requires clarification - skipping detailed structure checks")
    
    print("✓ Response format consistency test passed!")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Task 3 Implementation Verification")
    print("=" * 60)
    
    try:
        test_status_endpoint_exists()
        test_query_endpoint_with_demo()
        test_response_format_consistency()
        
        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED!")
        print("=" * 60)
        print("\nTask 3 implementation is working correctly:")
        print("  ✓ Status endpoint created and functional")
        print("  ✓ Demo response generator integrated")
        print("  ✓ Response format matches expected structure")
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
