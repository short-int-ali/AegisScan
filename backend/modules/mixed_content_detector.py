"""Mixed Content Detection Module

Detects insecure (HTTP) resources loaded on secure (HTTPS) pages.
"""

import re
from typing import List, Set
from urllib.parse import urlparse
import httpx

from models import Finding, Severity, OWASP


class MixedContentDetector:
    """Detects mixed content vulnerabilities on HTTPS pages."""

    # Patterns to find resource URLs in HTML
    RESOURCE_PATTERNS = [
        # Scripts (active mixed content - high risk)
        (r'<script[^>]+src=["\']([^"\']+)["\']', "script", True),
        # Stylesheets (active mixed content)
        (r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\']', "stylesheet", True),
        (r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']', "stylesheet", True),
        # Images (passive mixed content)
        (r'<img[^>]+src=["\']([^"\']+)["\']', "image", False),
        # Videos (passive mixed content)
        (r'<video[^>]+src=["\']([^"\']+)["\']', "video", False),
        (r'<source[^>]+src=["\']([^"\']+)["\']', "media source", False),
        # Audio (passive mixed content)
        (r'<audio[^>]+src=["\']([^"\']+)["\']', "audio", False),
        # Iframes (active mixed content)
        (r'<iframe[^>]+src=["\']([^"\']+)["\']', "iframe", True),
        # Object/Embed (active mixed content)
        (r'<object[^>]+data=["\']([^"\']+)["\']', "object", True),
        (r'<embed[^>]+src=["\']([^"\']+)["\']', "embed", True),
        # Form actions
        (r'<form[^>]+action=["\']([^"\']+)["\']', "form action", True),
    ]

    @classmethod
    def analyze(cls, url: str, response: httpx.Response) -> List[Finding]:
        """
        Analyze response for mixed content.

        Args:
            url: The target URL
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []
        parsed_url = urlparse(url)

        # Only check HTTPS pages
        if parsed_url.scheme != "https":
            return findings

        # Only analyze HTML responses
        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return findings

        html = response.text
        
        # Track findings to avoid duplicates
        active_mixed_resources: Set[str] = set()
        passive_mixed_resources: Set[str] = set()

        for pattern, resource_type, is_active in cls.RESOURCE_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            
            for resource_url in matches:
                # Skip empty, data URIs, or protocol-relative URLs
                if not resource_url or resource_url.startswith("data:"):
                    continue

                # Check if it's an HTTP URL
                if resource_url.startswith("http://"):
                    if is_active:
                        active_mixed_resources.add((resource_url, resource_type))
                    else:
                        passive_mixed_resources.add((resource_url, resource_type))

        # Report active mixed content (higher severity)
        if active_mixed_resources:
            resource_list = [f"{rtype}: {url}" for url, rtype in list(active_mixed_resources)[:5]]
            more_count = len(active_mixed_resources) - 5 if len(active_mixed_resources) > 5 else 0
            
            description = f"Active mixed content detected. The HTTPS page loads executable resources over insecure HTTP. Found {len(active_mixed_resources)} insecure resource(s)."
            if more_count > 0:
                description += f" Showing first 5, {more_count} more not shown."

            findings.append(Finding(
                category="Transport Security",
                title="Active Mixed Content Detected",
                severity=Severity.MEDIUM,
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description=f"{description} Resources: {', '.join(resource_list)}",
                impact="Active mixed content (scripts, stylesheets, iframes) loaded over HTTP can be modified by attackers, allowing them to inject malicious code and fully compromise the page.",
                remediation="Update all resource URLs to use HTTPS. Use protocol-relative URLs (//example.com) or absolute HTTPS URLs. Consider implementing Content-Security-Policy with upgrade-insecure-requests directive."
            ))

        # Report passive mixed content (lower severity)
        if passive_mixed_resources:
            resource_list = [f"{rtype}: {url}" for url, rtype in list(passive_mixed_resources)[:5]]
            more_count = len(passive_mixed_resources) - 5 if len(passive_mixed_resources) > 5 else 0
            
            description = f"Passive mixed content detected. The HTTPS page loads non-executable resources over insecure HTTP. Found {len(passive_mixed_resources)} insecure resource(s)."
            if more_count > 0:
                description += f" Showing first 5, {more_count} more not shown."

            findings.append(Finding(
                category="Transport Security",
                title="Passive Mixed Content Detected",
                severity=Severity.LOW,
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description=f"{description} Resources: {', '.join(resource_list)}",
                impact="Passive mixed content (images, videos) loaded over HTTP can be viewed or modified by network attackers, potentially leading to information disclosure or content manipulation.",
                remediation="Update all resource URLs to use HTTPS. Use protocol-relative URLs or absolute HTTPS URLs."
            ))

        return findings

