"""AegisScan - FastAPI Application

Main entry point for the passive web vulnerability scanner API.
V1: Includes platform hardening with rate limiting, security headers,
    and input sanitization.

DEPLOYMENT: This backend is designed to run on Render with Uvicorn.
Frontend is deployed separately on Vercel.
"""

import os
import re
import time
from collections import defaultdict
from typing import Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from models import ScanRequest, ScanResponse, ErrorResponse
from scanner import Scanner


# =============================================================================
# Rate Limiting Configuration
# =============================================================================
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))  # requests per window
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # window in seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting middleware."""
    
    def __init__(self, app, requests_limit: int = 10, window_seconds: int = 60):
        super().__init__(app)
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self.requests: dict = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only rate limit the /scan endpoint
        if request.url.path == "/scan" and request.method == "POST":
            client_ip = self._get_client_ip(request)
            current_time = time.time()
            
            # Clean old requests outside the window
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if current_time - req_time < self.window_seconds
            ]
            
            # Check rate limit
            if len(self.requests[client_ip]) >= self.requests_limit:
                return Response(
                    content='{"error": "Rate limit exceeded. Please try again later."}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": str(self.window_seconds)}
                )
            
            # Record this request
            self.requests[client_ip].append(current_time)
        
        response = await call_next(request)
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP, handling proxies."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Remove server header if present
        if "server" in response.headers:
            del response.headers["server"]
        
        return response


# =============================================================================
# CORS Configuration
# =============================================================================
def get_allowed_origins() -> list:
    """Get allowed CORS origins from environment or use permissive default."""
    origins_env = os.getenv("ALLOWED_ORIGINS", "")
    if origins_env:
        return [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    # Default: allow all origins (restrict in production)
    return ["*"]


# =============================================================================
# Input Sanitization
# =============================================================================
# URL validation pattern
URL_PATTERN = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

# Blocked private/internal networks
BLOCKED_PATTERNS = [
    r'^https?://localhost',
    r'^https?://127\.',
    r'^https?://0\.',
    r'^https?://10\.',
    r'^https?://172\.(1[6-9]|2[0-9]|3[0-1])\.',
    r'^https?://192\.168\.',
    r'^https?://169\.254\.',
    r'^https?://\[::1\]',
    r'^https?://\[fc',
    r'^https?://\[fd',
]


def sanitize_url(url: str) -> str:
    """Sanitize and validate URL input."""
    # Strip whitespace
    url = url.strip()
    
    # Basic length check
    if len(url) > 2048:
        raise ValueError("URL too long (max 2048 characters)")
    
    # Check for valid URL format
    if not URL_PATTERN.match(url):
        raise ValueError("Invalid URL format. URL must start with http:// or https://")
    
    # Block internal/private networks (SSRF prevention)
    for pattern in BLOCKED_PATTERNS:
        if re.match(pattern, url, re.IGNORECASE):
            raise ValueError("Scanning internal or private networks is not allowed")
    
    return url


# =============================================================================
# Create FastAPI App
# =============================================================================
app = FastAPI(
    title="AegisScan",
    description="Passive Web Vulnerability Scanner API - Read-only, non-intrusive security analysis",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add middlewares (order matters - last added is executed first)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    requests_limit=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW
)
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
        "version": "1.1.0",
        "description": "Passive Web Vulnerability Scanner with OWASP Top 10 Mapping",
        "endpoints": {
            "scan": "POST /scan",
            "health": "GET /health",
            "docs": "GET /docs",
        },
        "features": [
            "Transport Security Analysis",
            "Security Headers Check",
            "Cookie Security Analysis", 
            "Technology Disclosure Detection",
            "Mixed Content Detection",
            "Error Verbosity Detection",
            "Cache Privacy Analysis",
            "OWASP Top 10 Mapping",
            "Executive Summary & Risk Score"
        ]
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for deployment verification.
    Used by Render/other platforms to verify the service is running.
    """
    return {
        "status": "healthy",
        "service": "AegisScan API",
        "version": "1.1.0"
    }


@app.post("/scan", response_model=ScanResponse, responses={400: {"model": ErrorResponse}, 429: {"model": ErrorResponse}})
async def scan_url(request: ScanRequest):
    """
    Perform a passive security scan on the target URL.

    This endpoint performs non-intrusive security analysis including:
    - Transport security (HTTPS, TLS version, certificates)
    - Security headers analysis
    - Cookie security attributes
    - Technology disclosure detection
    - Mixed content detection
    - Error verbosity detection
    - Cache and privacy analysis
    - Passive input reflection detection
    - Public exposure checks

    All findings include OWASP Top 10 (2021) mapping.

    **Note**: This scanner is passive only. It does not perform any
    active exploitation, injection, or brute-force attacks.
    
    Args:
        request: ScanRequest containing the target URL
        
    Returns:
        ScanResponse with findings, summary, and executive summary
        
    Raises:
        HTTPException 400: Invalid URL or connection error
        HTTPException 429: Rate limit exceeded
        HTTPException 500: Internal server error
    """
    try:
        # Sanitize and validate input URL
        sanitized_url = sanitize_url(request.url)
        
        # Perform scan
        result = await Scanner.scan(sanitized_url)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
