#!/usr/bin/env python3
"""
Startup script for the AI Security Analyst API.
"""

import os
import sys
import logging
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
    """Start the API server."""
    try:
        import uvicorn
        from api.main import app
        
        # Configuration
        host = os.getenv("API_HOST", "0.0.0.0")
        port = int(os.getenv("API_PORT", "8000"))
        reload = os.getenv("API_RELOAD", "true").lower() == "true"
        
        logger.info(f"Starting AI Security Analyst API on {host}:{port}")
        logger.info(f"API documentation available at http://{host}:{port}/docs")
        
        # Start the server
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
        
    except ImportError as e:
        logger.error(f"Missing dependencies: {e}")
        logger.error("Please install requirements: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting API server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()