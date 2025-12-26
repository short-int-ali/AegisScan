"""Transport Security Analyzer Module

Analyzes HTTPS usage and TLS certificate details.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import httpx

from models import Finding, Severity


class TransportSecurityAnalyzer:
    """Analyzes transport layer security (HTTPS, TLS certificates)."""

    @classmethod
    async def analyze(cls, url: str, response: httpx.Response) -> List[Finding]:
        """
        Analyze transport security for the given URL.

        Args:
            url: The target URL
            response: The HTTP response from the target

        Returns:
            List of security findings
        """
        findings = []
        parsed = urlparse(url)

        # Check if HTTPS is used
        if parsed.scheme != "https":
            findings.append(Finding(
                category="Transport Security",
                title="Missing HTTPS",
                severity=Severity.HIGH,
                description="The target URL is using HTTP instead of HTTPS. All data transmitted between the client and server is unencrypted and can be intercepted.",
                remediation="Configure the web server to use HTTPS with a valid TLS certificate. Consider using Let's Encrypt for free certificates."
            ))
        else:
            # Analyze TLS certificate
            cert_findings = await cls._analyze_certificate(parsed.hostname, parsed.port or 443)
            findings.extend(cert_findings)

        # Check for HTTPS redirect
        if parsed.scheme == "http":
            redirect_finding = await cls._check_https_redirect(url)
            if redirect_finding:
                findings.append(redirect_finding)

        return findings

    @classmethod
    async def _analyze_certificate(cls, hostname: str, port: int) -> List[Finding]:
        """Analyze TLS certificate details."""
        findings = []

        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        # Check expiry
                        not_after = cert.get("notAfter")
                        if not_after:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)

                            if expiry < now:
                                findings.append(Finding(
                                    category="Transport Security",
                                    title="Expired TLS Certificate",
                                    severity=Severity.HIGH,
                                    description=f"The TLS certificate expired on {not_after}. Expired certificates cause browser warnings and indicate potential security issues.",
                                    remediation="Renew the TLS certificate immediately. Consider setting up automated certificate renewal."
                                ))
                            elif (expiry - now).days < 30:
                                findings.append(Finding(
                                    category="Transport Security",
                                    title="TLS Certificate Expiring Soon",
                                    severity=Severity.MEDIUM,
                                    description=f"The TLS certificate will expire on {not_after} (within 30 days). Plan for certificate renewal.",
                                    remediation="Renew the TLS certificate before expiration. Consider using automated renewal with Let's Encrypt."
                                ))

                        # Check issuer
                        issuer = cert.get("issuer")
                        if issuer:
                            issuer_dict = dict(x[0] for x in issuer)
                            org = issuer_dict.get("organizationName", "Unknown")
                            
                            # Self-signed certificate detection
                            subject = cert.get("subject")
                            if subject:
                                subject_dict = dict(x[0] for x in subject)
                                if issuer_dict == subject_dict:
                                    findings.append(Finding(
                                        category="Transport Security",
                                        title="Self-Signed TLS Certificate",
                                        severity=Severity.HIGH,
                                        description="The TLS certificate appears to be self-signed. Self-signed certificates are not trusted by browsers and can expose users to man-in-the-middle attacks.",
                                        remediation="Obtain a certificate from a trusted Certificate Authority (CA). Let's Encrypt provides free trusted certificates."
                                    ))

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                category="Transport Security",
                title="Invalid TLS Certificate",
                severity=Severity.HIGH,
                description=f"The TLS certificate failed verification: {str(e)}. This may indicate a misconfigured or compromised certificate.",
                remediation="Ensure the certificate is issued by a trusted CA, is not expired, and matches the hostname."
            ))
        except ssl.SSLError as e:
            findings.append(Finding(
                category="Transport Security",
                title="TLS Connection Error",
                severity=Severity.MEDIUM,
                description=f"Could not establish secure TLS connection: {str(e)}",
                remediation="Review TLS configuration and ensure modern cipher suites are enabled."
            ))
        except socket.timeout:
            findings.append(Finding(
                category="Transport Security",
                title="TLS Connection Timeout",
                severity=Severity.LOW,
                description="Connection timed out while attempting to verify TLS certificate.",
                remediation="Verify the server is accessible and TLS is properly configured."
            ))
        except Exception as e:
            # Don't crash on certificate analysis failures
            pass

        return findings

    @classmethod
    async def _check_https_redirect(cls, http_url: str) -> Optional[Finding]:
        """Check if HTTP URL redirects to HTTPS."""
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
                response = await client.get(http_url)
                
                if response.status_code in (301, 302, 307, 308):
                    location = response.headers.get("location", "")
                    if location.startswith("https://"):
                        return Finding(
                            category="Transport Security",
                            title="HTTP to HTTPS Redirect Present",
                            severity=Severity.LOW,
                            description="The server redirects HTTP traffic to HTTPS. This is good practice, but users may still be vulnerable during the initial HTTP request.",
                            remediation="Implement HSTS (HTTP Strict Transport Security) to ensure browsers always use HTTPS."
                        )
                
                return Finding(
                    category="Transport Security",
                    title="No HTTP to HTTPS Redirect",
                    severity=Severity.MEDIUM,
                    description="The HTTP version of the site does not redirect to HTTPS. Users accessing the site via HTTP will have unencrypted connections.",
                    remediation="Configure the server to redirect all HTTP traffic to HTTPS using a 301 redirect."
                )
        except Exception:
            return None

