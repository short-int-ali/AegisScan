from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class OWASPMapping(BaseModel):
    """OWASP Top 10 mapping for a finding."""
    id: str  # e.g., "A02"
    name: str  # e.g., "Cryptographic Failures"


# OWASP Top 10 (2021) constants for consistent mapping
class OWASP:
    A01_BROKEN_ACCESS = OWASPMapping(id="A01", name="Broken Access Control")
    A02_CRYPTO_FAILURES = OWASPMapping(id="A02", name="Cryptographic Failures")
    A03_INJECTION = OWASPMapping(id="A03", name="Injection")
    A04_INSECURE_DESIGN = OWASPMapping(id="A04", name="Insecure Design")
    A05_SECURITY_MISCONFIG = OWASPMapping(id="A05", name="Security Misconfiguration")
    A06_VULNERABLE_COMPONENTS = OWASPMapping(id="A06", name="Vulnerable and Outdated Components")
    A07_AUTH_FAILURES = OWASPMapping(id="A07", name="Identification and Authentication Failures")
    A08_INTEGRITY_FAILURES = OWASPMapping(id="A08", name="Software and Data Integrity Failures")
    A09_LOGGING_FAILURES = OWASPMapping(id="A09", name="Security Logging and Monitoring Failures")
    A10_SSRF = OWASPMapping(id="A10", name="Server-Side Request Forgery")


class Finding(BaseModel):
    category: str
    title: str
    severity: Severity
    owasp: OWASPMapping
    description: str
    impact: str
    remediation: str


class ScanSummary(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0


class ExecutiveSummary(BaseModel):
    """Executive summary with risk score and top risks."""
    total_findings: int
    risk_score: int  # 0-100 weighted score
    risk_level: str  # Critical, High, Medium, Low
    top_risks: List[str]  # Top 3 risk descriptions


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    target: str
    timestamp: str
    summary: ScanSummary
    executive_summary: ExecutiveSummary
    findings: List[Finding]


class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None

