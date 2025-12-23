from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Finding(BaseModel):
    category: str
    title: str
    severity: Severity
    description: str
    remediation: str


class ScanSummary(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    target: str
    timestamp: str
    summary: ScanSummary
    findings: List[Finding]


class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None

