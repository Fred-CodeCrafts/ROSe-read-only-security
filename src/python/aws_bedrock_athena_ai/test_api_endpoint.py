"""
Test the API endpoint to diagnose the chat interface error.
"""

import sys
sys.path.insert(0, 'src/python')

from fastapi.testclient import TestClient
from aws_bedrock_athena_ai.api.main import app

client = TestClient(app)

def test_status_endpoint():
    """Test the status endpoint"""
    print("Testing /api/v1/status endpoint...")
    response = client.get("/api/v1/status")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_security_question():
    """Test the security question endpoint"""
    print("Testing /api/v1/security/question endpoint...")
    
    test_question = {
        "question": "Are we being attacked right now?",
        "conversation_id": None,
        "user_role": "analyst"
    }
    
    try:
        response = client.post("/api/v1/security/question", json=test_question)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_status_endpoint()
    test_security_question()
