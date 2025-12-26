"""AegisScan - Main Scanner Module

Orchestrates all passive security analysis modules.
V1: Extended with OWASP mapping and executive summary.
"""

from datetime import datetime, timezone
from typing import List, Tuple
import httpx

from models import Finding, ScanSummary, ScanResponse, Severity, ExecutiveSummary
from modules import (
    URLNormalizer,
    TransportSecurityAnalyzer,
    SecurityHeaderAnalyzer,
    CookieAnalyzer,
    ReflectionDetector,
    ExposureChecker,
    TechnologyDetector,
    MixedContentDetector,
    ErrorVerbosityDetector,
    CachePrivacyAnalyzer,
)


class Scanner:
    """Main scanner that orchestrates all analysis modules."""

    DEFAULT_TIMEOUT = 30
    USER_AGENT = "AegisScan/1.0 (Passive Security Scanner)"

    # Severity weights for risk score calculation
    SEVERITY_WEIGHTS = {
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
    }

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
            # 1. Transport Security Analysis (includes TLS version check)
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

            # 4. Technology Disclosure Detection
            tech_findings = TechnologyDetector.analyze(response)
            findings.extend(tech_findings)

            # 5. Mixed Content Detection
            mixed_content_findings = MixedContentDetector.analyze(
                normalized_url, response
            )
            findings.extend(mixed_content_findings)

            # 6. Error Verbosity Detection
            error_findings = ErrorVerbosityDetector.analyze(response)
            findings.extend(error_findings)

            # 7. Cache & Privacy Analysis
            cache_findings = CachePrivacyAnalyzer.analyze(response)
            findings.extend(cache_findings)

            # 8. Passive Reflection Detection
            reflection_findings = await ReflectionDetector.analyze(
                normalized_url, client
            )
            findings.extend(reflection_findings)

            # 9. Public Exposure Check
            exposure_findings = await ExposureChecker.analyze(normalized_url, client)
            findings.extend(exposure_findings)

        # Calculate summary and executive summary
        summary = cls._calculate_summary(findings)
        executive_summary = cls._generate_executive_summary(findings, summary)

        # Build response
        return ScanResponse(
            target=normalized_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            executive_summary=executive_summary,
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

    @classmethod
    def _generate_executive_summary(
        cls, findings: List[Finding], summary: ScanSummary
    ) -> ExecutiveSummary:
        """
        Generate executive summary with risk score and top risks.
        
        Risk Score Calculation (0-100):
        - Based on weighted severity counts
        - Normalized to 100 scale
        - Higher score = higher risk
        """
        total_findings = summary.high + summary.medium + summary.low

        # Calculate weighted risk score
        raw_score = (
            summary.high * cls.SEVERITY_WEIGHTS[Severity.HIGH] +
            summary.medium * cls.SEVERITY_WEIGHTS[Severity.MEDIUM] +
            summary.low * cls.SEVERITY_WEIGHTS[Severity.LOW]
        )

        # Normalize to 0-100 scale (cap at 100)
        # Base assumption: 10 high findings = 100 score
        max_expected_score = 100
        risk_score = min(100, int((raw_score / max_expected_score) * 100))

        # Determine risk level
        if summary.high >= 3 or risk_score >= 70:
            risk_level = "Critical"
        elif summary.high >= 1 or risk_score >= 40:
            risk_level = "High"
        elif summary.medium >= 3 or risk_score >= 20:
            risk_level = "Medium"
        elif total_findings > 0:
            risk_level = "Low"
        else:
            risk_level = "Minimal"

        # Get top 3 risks (prioritize by severity, then by category diversity)
        top_risks = cls._get_top_risks(findings)

        return ExecutiveSummary(
            total_findings=total_findings,
            risk_score=risk_score,
            risk_level=risk_level,
            top_risks=top_risks,
        )

    @classmethod
    def _get_top_risks(cls, findings: List[Finding]) -> List[str]:
        """Get the top 3 most critical risks as descriptions."""
        if not findings:
            return ["No security issues detected"]

        # Sort by severity (HIGH first)
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order[f.severity]
        )

        # Get top 3 unique categories/risks
        top_risks = []
        seen_categories = set()

        for finding in sorted_findings:
            if len(top_risks) >= 3:
                break
            
            # Create a risk description
            risk_desc = f"{finding.severity.value}: {finding.title}"
            
            # Prefer diverse categories
            if finding.category not in seen_categories:
                top_risks.append(risk_desc)
                seen_categories.add(finding.category)
            elif len(top_risks) < 3 and risk_desc not in top_risks:
                # If we haven't hit 3 yet, allow same category
                top_risks.append(risk_desc)

        return top_risks if top_risks else ["No significant risks identified"]

