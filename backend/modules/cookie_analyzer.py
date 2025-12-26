"""Cookie Analyzer Module

Analyzes cookies for security attributes.
"""

from typing import List, Dict
from http.cookies import SimpleCookie
import httpx

from models import Finding, Severity, OWASP


class CookieAnalyzer:
    """Analyzes Set-Cookie headers for security attributes."""

    @classmethod
    def analyze(cls, response: httpx.Response) -> List[Finding]:
        """
        Analyze cookies in the HTTP response.

        Args:
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []

        # Get all Set-Cookie headers
        cookies = response.headers.get_list("set-cookie")

        if not cookies:
            return findings

        for cookie_str in cookies:
            cookie_findings = cls._analyze_cookie(cookie_str)
            findings.extend(cookie_findings)

        return findings

    @classmethod
    def _analyze_cookie(cls, cookie_str: str) -> List[Finding]:
        """Analyze a single cookie string for security issues."""
        findings = []

        # Parse cookie attributes
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            return findings

        # Get cookie name
        cookie_name = parts[0].split("=")[0] if "=" in parts[0] else "Unknown"

        # Convert attributes to lowercase for checking
        attributes_lower = [p.lower() for p in parts[1:]]
        attribute_dict = {}
        for attr in attributes_lower:
            if "=" in attr:
                key, value = attr.split("=", 1)
                attribute_dict[key.strip()] = value.strip()
            else:
                attribute_dict[attr.strip()] = True

        # Check for Secure flag
        if "secure" not in attribute_dict:
            findings.append(Finding(
                category="Cookie Security",
                title=f"Cookie '{cookie_name}' Missing Secure Flag",
                severity=Severity.MEDIUM,
                owasp=OWASP.A07_AUTH_FAILURES,
                description=f"The cookie '{cookie_name}' does not have the Secure flag set. This means the cookie can be transmitted over unencrypted HTTP connections.",
                impact="If users access the site over HTTP, the cookie (potentially containing session tokens) can be intercepted by network attackers.",
                remediation="Add the Secure flag to the cookie to ensure it is only sent over HTTPS connections."
            ))

        # Check for HttpOnly flag
        if "httponly" not in attribute_dict:
            findings.append(Finding(
                category="Cookie Security",
                title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                severity=Severity.MEDIUM,
                owasp=OWASP.A07_AUTH_FAILURES,
                description=f"The cookie '{cookie_name}' does not have the HttpOnly flag set. This means the cookie can be accessed by client-side JavaScript, making it vulnerable to XSS attacks.",
                impact="If an XSS vulnerability exists, attackers can steal this cookie using JavaScript and potentially hijack user sessions.",
                remediation="Add the HttpOnly flag to the cookie to prevent client-side script access."
            ))

        # Check for SameSite attribute
        samesite = attribute_dict.get("samesite")
        if not samesite:
            findings.append(Finding(
                category="Cookie Security",
                title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                severity=Severity.MEDIUM,
                owasp=OWASP.A07_AUTH_FAILURES,
                description=f"The cookie '{cookie_name}' does not have the SameSite attribute set. This could make the application vulnerable to CSRF attacks.",
                impact="Without SameSite, the cookie is sent with cross-site requests, potentially allowing attackers to perform actions on behalf of authenticated users.",
                remediation="Add the SameSite attribute with 'Strict' or 'Lax' value to prevent cross-site request forgery."
            ))
        elif samesite.lower() == "none":
            # SameSite=None requires Secure flag
            if "secure" not in attribute_dict:
                findings.append(Finding(
                    category="Cookie Security",
                    title=f"Cookie '{cookie_name}' Has Insecure SameSite Configuration",
                    severity=Severity.MEDIUM,
                    owasp=OWASP.A07_AUTH_FAILURES,
                    description=f"The cookie '{cookie_name}' has SameSite=None but is missing the Secure flag. Modern browsers will reject this cookie.",
                    impact="The cookie may not function as expected in modern browsers, potentially breaking authentication or session management.",
                    remediation="Either add the Secure flag when using SameSite=None, or change SameSite to 'Strict' or 'Lax'."
                ))

        return findings

