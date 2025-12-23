"""Passive Input Reflection Detection Module

Detects reflected input in responses using benign markers only.
No scripts or payloads are used - this is purely passive detection.
"""

import uuid
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import httpx

from backend.models import Finding, Severity


class ReflectionDetector:
    """Detects potential input reflection vulnerabilities passively."""

    # Benign marker prefix - clearly identifies our test strings
    MARKER_PREFIX = "AEGIS"

    @classmethod
    async def analyze(cls, url: str, client: httpx.AsyncClient) -> List[Finding]:
        """
        Analyze URL for potential input reflection.

        Uses benign markers only - no XSS payloads or scripts.

        Args:
            url: The target URL
            client: HTTP client to use

        Returns:
            List of security findings
        """
        findings = []

        # Generate a unique benign marker
        marker = f"{cls.MARKER_PREFIX}{uuid.uuid4().hex[:8]}"

        # Test reflection in URL parameters
        param_findings = await cls._test_parameter_reflection(url, marker, client)
        findings.extend(param_findings)

        return findings

    @classmethod
    async def _test_parameter_reflection(
        cls, url: str, marker: str, client: httpx.AsyncClient
    ) -> List[Finding]:
        """Test if URL parameters are reflected in the response."""
        findings = []
        parsed = urlparse(url)

        # Get existing query parameters
        existing_params = parse_qs(parsed.query)

        # Test each existing parameter
        for param_name in existing_params:
            test_url = cls._build_test_url(url, param_name, marker)
            
            try:
                response = await client.get(test_url, timeout=10)
                
                if marker in response.text:
                    findings.append(Finding(
                        category="Input Handling",
                        title=f"Input Reflection Detected in Parameter '{param_name}'",
                        severity=Severity.LOW,
                        description=f"The parameter '{param_name}' appears to be reflected in the response. While this test uses benign markers, reflected input could potentially be exploited if proper output encoding is not implemented.",
                        remediation="Ensure all user input is properly encoded before being included in HTML responses. Implement Content-Security-Policy headers to mitigate potential XSS risks."
                    ))
            except Exception:
                # Don't report errors for reflection testing
                pass

        # Also test with a common test parameter if no existing params
        if not existing_params:
            test_params = ["q", "search", "query", "id", "page"]
            
            for param_name in test_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={marker}"
                
                try:
                    response = await client.get(test_url, timeout=10)
                    
                    if marker in response.text:
                        findings.append(Finding(
                            category="Input Handling",
                            title=f"Input Reflection Detected in Parameter '{param_name}'",
                            severity=Severity.LOW,
                            description=f"The parameter '{param_name}' appears to be reflected in the response. While this test uses benign markers, reflected input could potentially be exploited if proper output encoding is not implemented.",
                            remediation="Ensure all user input is properly encoded before being included in HTML responses. Implement Content-Security-Policy headers to mitigate potential XSS risks."
                        ))
                        # Only report first reflection found in test params
                        break
                except Exception:
                    pass

        return findings

    @classmethod
    def _build_test_url(cls, url: str, param_name: str, marker: str) -> str:
        """Build a test URL with the marker in the specified parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [marker]

        new_query = urlencode(params, doseq=True)
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

