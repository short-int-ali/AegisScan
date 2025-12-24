"""AegisScan - FastAPI Application

Main entry point for the passive web vulnerability scanner API.

DEPLOYMENT: This backend is designed to run on Render with Uvicorn.
Frontend is deployed separately on Vercel.
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.models import ScanRequest, ScanResponse, ErrorResponse
from backend.scanner import Scanner


# =============================================================================
# CORS Configuration
# =============================================================================
# For production, replace "*" with your actual Vercel frontend URL(s)
# Example: ["https://your-app.vercel.app", "https://your-custom-domain.com"]
# 
# You can set ALLOWED_ORIGINS environment variable as comma-separated URLs:
# ALLOWED_ORIGINS=https://aegisscan.vercel.app,https://aegisscan.com
# =============================================================================
def get_allowed_origins() -> list:
    """Get allowed CORS origins from environment or use permissive default."""
    origins_env = os.getenv("ALLOWED_ORIGINS", "")
    if origins_env:
        return [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    # Default: allow all origins (restrict in production)
    return ["*"]


# Create FastAPI app
app = FastAPI(
    title="AegisScan",
    description="Passive Web Vulnerability Scanner API - Read-only, non-intrusive security analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/")
async def root():
    """Root endpoint - API information."""
    return {
        "service": "AegisScan API",
        "version": "1.0.0",
        "description": "Passive Web Vulnerability Scanner",
        "endpoints": {
            "scan": "POST /scan",
            "health": "GET /health",
            "docs": "GET /docs",
        }
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for deployment verification.
    Used by Railway/other platforms to verify the service is running.
    """
    return {
        "status": "healthy",
        "service": "AegisScan API",
        "version": "1.0.0"
    }


@app.post("/scan", response_model=ScanResponse, responses={400: {"model": ErrorResponse}})
async def scan_url(request: ScanRequest):
    """
    Perform a passive security scan on the target URL.

    This endpoint performs non-intrusive security analysis including:
    - Transport security (HTTPS, TLS certificates)
    - Security headers analysis
    - Cookie security attributes
    - Passive input reflection detection
    - Public exposure checks

    **Note**: This scanner is passive only. It does not perform any
    active exploitation, injection, or brute-force attacks.
    
    Args:
        request: ScanRequest containing the target URL
        
    Returns:
        ScanResponse with findings and summary
        
    Raises:
        HTTPException 400: Invalid URL or connection error
        HTTPException 500: Internal server error
    """
    try:
        result = await Scanner.scan(request.url)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
