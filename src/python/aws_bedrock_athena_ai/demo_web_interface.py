#!/usr/bin/env python3
"""
Demo script for the AI Security Analyst Web Interface.

This script starts the API server with the web interface for demonstration purposes.
"""

import os
import sys
import logging
import webbrowser
import time
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Start the web interface demo."""
    try:
        import uvicorn
        from api.main import app, DEMO_KEY
        
        # Configuration
        host = "127.0.0.1"
        port = 8000
        
        logger.info("=" * 60)
        logger.info("AI Security Analyst - Web Interface Demo")
        logger.info("=" * 60)
        logger.info(f"Starting server on http://{host}:{port}")
        logger.info(f"Demo API Key: {DEMO_KEY['api_key']}")
        logger.info("=" * 60)
        
        # Open browser after a short delay
        def open_browser():
            time.sleep(2)
            webbrowser.open(f"http://{host}:{port}")
        
        import threading
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        
        # Start the server
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info"
        )
        
    except ImportError as e:
        logger.error(f"Missing dependencies: {e}")
        logger.error("Please install requirements: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting demo: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()