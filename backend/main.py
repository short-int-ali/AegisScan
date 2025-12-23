"""AegisScan - FastAPI Application

Main entry point for the passive web vulnerability scanner.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from backend.models import ScanRequest, ScanResponse, ErrorResponse
from backend.scanner import Scanner


# Create FastAPI app
app = FastAPI(
    title="AegisScan",
    description="Passive Web Vulnerability Scanner - Read-only, non-intrusive security analysis",
    version="1.0.0",
)

# Add CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    """
    try:
        result = await Scanner.scan(request.url)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "AegisScan"}


# Serve frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")


@app.get("/")
async def serve_frontend():
    """Serve the frontend application."""
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "AegisScan API - Use POST /scan to scan a URL"}


# Mount static files if frontend exists
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

