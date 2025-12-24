"""AegisScan - Root Entry Point

This file serves as the entry point for Render deployment.
It re-exports the FastAPI app from the backend module.

DEPLOYMENT COMMAND (Render):
    uvicorn main:app --host 0.0.0.0 --port $PORT

ENVIRONMENT VARIABLES:
    PORT            - Server port (set automatically by Render)
    ALLOWED_ORIGINS - Comma-separated list of allowed CORS origins
                      Example: https://aegisscan.vercel.app,https://example.com
"""

# Re-export the FastAPI app for Uvicorn
from backend.main import app

# This allows running with: uvicorn main:app
__all__ = ["app"]
