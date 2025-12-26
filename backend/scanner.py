"""AegisScan - Main Scanner Module

Orchestrates all passive security analysis modules.
"""

from datetime import datetime, timezone
from typing import List
import httpx

from models import Finding, ScanSummary, ScanResponse, Severity
from modules import (
    URLNormalizer,
    TransportSecurityAnalyzer,
    SecurityHeaderAnalyzer,
    CookieAnalyzer,
    ReflectionDetector,
    ExposureChecker,
)


class Scanner:
    """Main scanner that orchestrates all analysis modules."""

    DEFAULT_TIMEOUT = 30
    USER_AGENT = "AegisScan/1.0 (Passive Security Scanner)"

    @classmethod
    async def scan(cls, url: str) -> ScanResponse:
        """
        Perform a passive security scan on the target URL.

        Args:
            url: The URL to scan

        Returns:
            ScanResponse with all findings

        Raises:
            ValueError: If URL is invalid or blocked
        """
        # Normalize and validate URL
        is_valid, normalized_url, error = URLNormalizer.normalize(url)
        if not is_valid:
            raise ValueError(error)

        findings: List[Finding] = []

        # Configure HTTP client
        async with httpx.AsyncClient(
            timeout=cls.DEFAULT_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": cls.USER_AGENT},
            verify=True,  # Verify TLS certificates
        ) as client:
            # Fetch the main page
            try:
                response = await client.get(normalized_url)
            except httpx.TimeoutException:
                raise ValueError(f"Connection to {normalized_url} timed out")
            except httpx.ConnectError as e:
                raise ValueError(f"Could not connect to {normalized_url}: {str(e)}")
            except httpx.RequestError as e:
                raise ValueError(f"Request failed: {str(e)}")

            # Run all analysis modules
            # 1. Transport Security Analysis
            transport_findings = await TransportSecurityAnalyzer.analyze(
                normalized_url, response
            )
            findings.extend(transport_findings)

            # 2. Security Header Analysis
            header_findings = SecurityHeaderAnalyzer.analyze(response)
            findings.extend(header_findings)

            # 3. Cookie Analysis
            cookie_findings = CookieAnalyzer.analyze(response)
            findings.extend(cookie_findings)

            # 4. Passive Reflection Detection
            reflection_findings = await ReflectionDetector.analyze(
                normalized_url, client
            )
            findings.extend(reflection_findings)

            # 5. Public Exposure Check
            exposure_findings = await ExposureChecker.analyze(normalized_url, client)
            findings.extend(exposure_findings)

        # Calculate summary
        summary = cls._calculate_summary(findings)

        # Build response
        return ScanResponse(
            target=normalized_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            findings=findings,
        )

    @classmethod
    def _calculate_summary(cls, findings: List[Finding]) -> ScanSummary:
        """Calculate the summary counts from findings."""
        summary = ScanSummary()

        for finding in findings:
            if finding.severity == Severity.HIGH:
                summary.high += 1
            elif finding.severity == Severity.MEDIUM:
                summary.medium += 1
            elif finding.severity == Severity.LOW:
                summary.low += 1

        return summary

