"""Server & Technology Disclosure Analyzer Module

Detects technology and version information leaked through headers,
HTML meta tags, and other response content.
"""

import re
from typing import List, Dict, Tuple
import httpx

from models import Finding, Severity, OWASP


class TechnologyDetector:
    """Detects technology disclosure in responses."""

    # HTML patterns for technology detection
    HTML_PATTERNS = [
        # Generator meta tags
        {
            "pattern": r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            "name": "Generator Meta Tag",
            "extract_group": 1,
        },
        {
            "pattern": r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            "name": "Generator Meta Tag",
            "extract_group": 1,
        },
        # WordPress detection
        {
            "pattern": r'/wp-content/',
            "name": "WordPress",
            "fixed_value": "WordPress CMS",
        },
        {
            "pattern": r'/wp-includes/',
            "name": "WordPress",
            "fixed_value": "WordPress CMS",
        },
        # Drupal detection
        {
            "pattern": r'Drupal\.settings',
            "name": "Drupal",
            "fixed_value": "Drupal CMS",
        },
        {
            "pattern": r'/sites/default/files/',
            "name": "Drupal",
            "fixed_value": "Drupal CMS",
        },
        # Joomla detection
        {
            "pattern": r'/media/jui/',
            "name": "Joomla",
            "fixed_value": "Joomla CMS",
        },
        # React/Vue/Angular detection
        {
            "pattern": r'<div[^>]+id=["\']root["\'][^>]*></div>.*react',
            "name": "React",
            "fixed_value": "React Framework",
        },
        {
            "pattern": r'ng-app|ng-controller|angular\.module',
            "name": "AngularJS",
            "fixed_value": "AngularJS Framework",
        },
        {
            "pattern": r'<div[^>]+id=["\']app["\'][^>]*></div>.*vue',
            "name": "Vue.js",
            "fixed_value": "Vue.js Framework",
        },
        # jQuery with version
        {
            "pattern": r'jquery[.-](\d+\.\d+(?:\.\d+)?)',
            "name": "jQuery",
            "extract_group": 1,
            "prefix": "jQuery ",
        },
        # Bootstrap
        {
            "pattern": r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)',
            "name": "Bootstrap",
            "extract_group": 1,
            "prefix": "Bootstrap ",
        },
    ]

    # Headers that disclose technology information
    DISCLOSURE_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "X-Drupal-Cache",
        "X-Drupal-Dynamic-Cache",
        "X-Varnish",
        "X-Runtime",
        "X-Version",
    ]

    @classmethod
    def analyze(cls, response: httpx.Response) -> List[Finding]:
        """
        Analyze response for technology disclosure.

        Args:
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []
        detected_technologies = set()

        # Check headers for technology disclosure
        header_findings = cls._analyze_headers(response.headers, detected_technologies)
        findings.extend(header_findings)

        # Check HTML content for technology disclosure
        if "text/html" in response.headers.get("content-type", ""):
            html_findings = cls._analyze_html(response.text, detected_technologies)
            findings.extend(html_findings)

        return findings

    @classmethod
    def _analyze_headers(
        cls, headers: httpx.Headers, detected: set
    ) -> List[Finding]:
        """Analyze headers for technology disclosure."""
        findings = []

        for header_name in cls.DISCLOSURE_HEADERS:
            header_value = headers.get(header_name)
            if header_value and header_name not in detected:
                # Check if it contains version information (more severe)
                has_version = any(char.isdigit() for char in header_value)
                
                if header_name in ("Server", "X-Powered-By"):
                    # These are already handled in header_analyzer, skip
                    continue

                detected.add(header_name)
                
                severity = Severity.LOW if not has_version else Severity.MEDIUM
                
                findings.append(Finding(
                    category="Information Disclosure",
                    title=f"Technology Disclosure via {header_name}",
                    severity=severity,
                    owasp=OWASP.A05_SECURITY_MISCONFIG,
                    description=f"The {header_name} header reveals technology information: '{header_value}'.",
                    impact="Technology and version disclosure helps attackers identify specific vulnerabilities and exploits applicable to the detected software.",
                    remediation=f"Remove or suppress the {header_name} header in server configuration."
                ))

        return findings

    @classmethod
    def _analyze_html(cls, html: str, detected: set) -> List[Finding]:
        """Analyze HTML content for technology disclosure."""
        findings = []
        html_lower = html.lower()

        for pattern_config in cls.HTML_PATTERNS:
            pattern = pattern_config["pattern"]
            name = pattern_config["name"]

            # Skip if already detected
            if name in detected:
                continue

            match = re.search(pattern, html_lower if "fixed_value" in pattern_config else html, re.IGNORECASE)
            if match:
                detected.add(name)

                # Extract the technology value
                if "fixed_value" in pattern_config:
                    tech_value = pattern_config["fixed_value"]
                elif "extract_group" in pattern_config:
                    extracted = match.group(pattern_config["extract_group"])
                    prefix = pattern_config.get("prefix", "")
                    tech_value = f"{prefix}{extracted}"
                else:
                    tech_value = name

                # Check if version is included
                has_version = any(char.isdigit() for char in tech_value)
                severity = Severity.MEDIUM if has_version else Severity.LOW

                findings.append(Finding(
                    category="Information Disclosure",
                    title=f"{name} Detected",
                    severity=severity,
                    owasp=OWASP.A05_SECURITY_MISCONFIG,
                    description=f"The HTML content reveals technology information: {tech_value}.",
                    impact="Knowing the exact technology stack allows attackers to search for known vulnerabilities specific to these technologies.",
                    remediation="Remove generator meta tags, minimize technology fingerprints in HTML, and review third-party library references."
                ))

        return findings

