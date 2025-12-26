"""Security Header Analyzer Module

Checks for presence and configuration of security-related HTTP headers.
"""

from typing import List, Dict, Optional
import httpx

from models import Finding, Severity


class SecurityHeaderAnalyzer:
    """Analyzes HTTP security headers."""

    # Security headers to check with their configurations
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "description": "HTTP Strict Transport Security (HSTS) header is missing. This header ensures browsers only connect via HTTPS, preventing downgrade attacks.",
            "remediation": "Add the Strict-Transport-Security header with appropriate directives, e.g., 'max-age=31536000; includeSubDomains'.",
            "weak_check": lambda v: "max-age" not in v.lower() or int(next((x.split("=")[1] for x in v.split(";") if "max-age" in x.lower()), "0")) < 31536000
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS attacks by controlling which resources can be loaded.",
            "remediation": "Implement a Content-Security-Policy header. Start with a report-only policy to identify issues before enforcement.",
            "weak_check": lambda v: "unsafe-inline" in v.lower() or "unsafe-eval" in v.lower()
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "X-Frame-Options header is missing. This header prevents clickjacking attacks by controlling whether the page can be embedded in frames.",
            "remediation": "Add the X-Frame-Options header with 'DENY' or 'SAMEORIGIN' value.",
            "weak_check": lambda v: v.upper() not in ("DENY", "SAMEORIGIN")
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "X-Content-Type-Options header is missing. This header prevents MIME-sniffing attacks.",
            "remediation": "Add the X-Content-Type-Options header with 'nosniff' value.",
            "weak_check": lambda v: v.lower() != "nosniff"
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Referrer-Policy header is missing. This header controls how much referrer information is sent with requests.",
            "remediation": "Add the Referrer-Policy header with an appropriate value such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
            "weak_check": lambda v: v.lower() in ("unsafe-url", "no-referrer-when-downgrade")
        },
    }

    @classmethod
    def analyze(cls, response: httpx.Response) -> List[Finding]:
        """
        Analyze security headers in the HTTP response.

        Args:
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []
        headers = response.headers

        for header_name, config in cls.SECURITY_HEADERS.items():
            header_value = headers.get(header_name)

            if header_value is None:
                # Header is missing
                findings.append(Finding(
                    category="Security Headers",
                    title=f"Missing {header_name} Header",
                    severity=config["severity"],
                    description=config["description"],
                    remediation=config["remediation"]
                ))
            else:
                # Check for weak configuration
                try:
                    if config["weak_check"](header_value):
                        findings.append(Finding(
                            category="Security Headers",
                            title=f"Weak {header_name} Configuration",
                            severity=Severity.LOW,
                            description=f"The {header_name} header is present but may have a weak configuration. Current value: '{header_value}'",
                            remediation=config["remediation"]
                        ))
                except Exception:
                    # Skip weak check if parsing fails
                    pass

        # Check for potentially dangerous headers
        dangerous_headers = cls._check_dangerous_headers(headers)
        findings.extend(dangerous_headers)

        return findings

    @classmethod
    def _check_dangerous_headers(cls, headers: httpx.Headers) -> List[Finding]:
        """Check for headers that might leak sensitive information."""
        findings = []

        # Server header with version info
        server = headers.get("Server")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                category="Security Headers",
                title="Server Version Disclosure",
                severity=Severity.LOW,
                description=f"The Server header discloses version information: '{server}'. This information could help attackers identify known vulnerabilities.",
                remediation="Configure the web server to remove or minimize version information in the Server header."
            ))

        # X-Powered-By header
        powered_by = headers.get("X-Powered-By")
        if powered_by:
            findings.append(Finding(
                category="Security Headers",
                title="Technology Stack Disclosure",
                severity=Severity.LOW,
                description=f"The X-Powered-By header discloses technology information: '{powered_by}'. This could help attackers identify potential vulnerabilities.",
                remediation="Remove the X-Powered-By header from server responses."
            ))

        # X-AspNet-Version header
        aspnet_version = headers.get("X-AspNet-Version")
        if aspnet_version:
            findings.append(Finding(
                category="Security Headers",
                title="ASP.NET Version Disclosure",
                severity=Severity.LOW,
                description=f"The X-AspNet-Version header discloses framework version: '{aspnet_version}'.",
                remediation="Disable the X-AspNet-Version header in web.config."
            ))

        return findings

