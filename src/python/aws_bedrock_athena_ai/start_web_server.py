"""
Start the web server for the AI Security Analyst interface.
"""

import sys
import os

# Add src/python to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import uvicorn
from aws_bedrock_athena_ai.api.main import app

if __name__ == "__main__":
    print("=" * 80)
    print("AI Security Analyst - Web Interface")
    print("=" * 80)
    print()
    print("Starting server...")
    print("Open your browser to: http://localhost:8000")
    print()
    print("Press CTRL+C to stop the server")
    print("=" * 80)
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
