"""Cache & Privacy Risk Analyzer Module

Analyzes cache-related headers for potential privacy and security risks.
"""

from typing import List, Optional
import httpx

from models import Finding, Severity, OWASP


class CachePrivacyAnalyzer:
    """Analyzes cache headers for security and privacy risks."""

    # Headers that indicate sensitive content
    SENSITIVE_INDICATORS = [
        "set-cookie",
        "authorization",
        "x-auth-token",
        "x-api-key",
    ]

    @classmethod
    def analyze(cls, response: httpx.Response) -> List[Finding]:
        """
        Analyze response for cache-related security issues.

        Args:
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []
        headers = response.headers

        # Get cache-related headers
        cache_control = headers.get("cache-control", "").lower()
        pragma = headers.get("pragma", "").lower()
        expires = headers.get("expires", "")
        vary = headers.get("vary", "").lower()

        # Check if response appears to contain sensitive data
        has_sensitive_headers = any(
            headers.get(h) for h in cls.SENSITIVE_INDICATORS
        )
        
        # Check content for signs of dynamic/sensitive content
        content_type = headers.get("content-type", "").lower()
        is_html = "text/html" in content_type
        is_json = "application/json" in content_type

        # Analyze cache configuration
        findings.extend(cls._analyze_cache_config(
            cache_control, pragma, expires, vary,
            has_sensitive_headers, is_html, is_json
        ))

        return findings

    @classmethod
    def _analyze_cache_config(
        cls,
        cache_control: str,
        pragma: str,
        expires: str,
        vary: str,
        has_sensitive_headers: bool,
        is_html: bool,
        is_json: bool
    ) -> List[Finding]:
        """Analyze cache configuration for issues."""
        findings = []

        # Parse cache-control directives
        has_no_store = "no-store" in cache_control
        has_no_cache = "no-cache" in cache_control
        has_private = "private" in cache_control
        has_public = "public" in cache_control
        has_max_age = "max-age" in cache_control

        # Check for potentially sensitive responses without proper cache control
        if has_sensitive_headers:
            if not has_no_store:
                findings.append(Finding(
                    category="Cache Security",
                    title="Sensitive Response May Be Cached",
                    severity=Severity.MEDIUM,
                    owasp=OWASP.A05_SECURITY_MISCONFIG,
                    description="The response contains sensitive headers (such as Set-Cookie) but lacks 'Cache-Control: no-store' directive. This may allow sensitive data to be stored in browser or proxy caches.",
                    impact="Sensitive data like session tokens or user information may persist in shared caches, potentially exposing it to other users of the same device or network.",
                    remediation="Add 'Cache-Control: no-store' header to prevent caching of sensitive responses. For additional protection, also add 'Pragma: no-cache' for HTTP/1.0 compatibility."
                ))

        # Check for public caching of dynamic content
        if has_public and (is_html or is_json):
            if not has_sensitive_headers:  # Avoid duplicate warnings
                findings.append(Finding(
                    category="Cache Security",
                    title="Dynamic Content Marked as Publicly Cacheable",
                    severity=Severity.LOW,
                    owasp=OWASP.A05_SECURITY_MISCONFIG,
                    description="The response uses 'Cache-Control: public' for dynamic content (HTML/JSON). If this content is user-specific, it could be served to other users from proxy caches.",
                    impact="User-specific content marked as public may be cached by proxies and served to other users, potentially leaking personal information.",
                    remediation="Use 'Cache-Control: private' for user-specific content, or 'no-store' for sensitive content. Only use 'public' for truly static, non-sensitive resources."
                ))

        # Check for missing cache headers on HTML pages
        if is_html and not cache_control and not pragma:
            findings.append(Finding(
                category="Cache Security",
                title="Missing Cache-Control Header",
                severity=Severity.LOW,
                owasp=OWASP.A05_SECURITY_MISCONFIG,
                description="The HTML response does not include Cache-Control headers. Caching behavior will be determined by browser defaults and heuristics, which may not be appropriate for your content.",
                impact="Without explicit cache control, browsers and proxies may cache content longer than intended, potentially serving stale or sensitive content.",
                remediation="Add appropriate Cache-Control headers based on content sensitivity: 'no-store' for sensitive content, 'private, max-age=X' for user-specific content, or 'public, max-age=X' for static content."
            ))

        # Check for vary header on dynamic content
        if (is_html or is_json) and has_max_age and not has_private and not has_no_store:
            if "cookie" not in vary and "authorization" not in vary:
                findings.append(Finding(
                    category="Cache Security",
                    title="Cacheable Response Missing Vary Header",
                    severity=Severity.LOW,
                    owasp=OWASP.A05_SECURITY_MISCONFIG,
                    description="The cacheable response does not include appropriate Vary headers. If content varies by user (via cookies or auth), the same cached response may be served to different users.",
                    impact="Without proper Vary headers, proxy caches may serve the same cached content to different users, even if the content should be personalized.",
                    remediation="Add 'Vary: Cookie' or 'Vary: Authorization' headers if content varies by user. Alternatively, use 'Cache-Control: private' to prevent proxy caching."
                ))

        return findings

