"""Transport Security Analyzer Module

Analyzes HTTPS usage, TLS certificate details, and TLS version strength.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from models import Finding, Severity, OWASP


class TransportSecurityAnalyzer:
    """Analyzes transport layer security (HTTPS, TLS certificates, TLS version)."""

    # TLS versions and their security status
    TLS_VERSIONS = {
        ssl.TLSVersion.TLSv1: ("TLS 1.0", Severity.HIGH, True),      # Deprecated
        ssl.TLSVersion.TLSv1_1: ("TLS 1.1", Severity.MEDIUM, True),  # Deprecated
        ssl.TLSVersion.TLSv1_2: ("TLS 1.2", Severity.LOW, False),    # Acceptable
        ssl.TLSVersion.TLSv1_3: ("TLS 1.3", None, False),            # Preferred
    }

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
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description="The target URL is using HTTP instead of HTTPS. All data transmitted between the client and server is unencrypted and can be intercepted.",
                impact="Attackers on the same network can intercept, read, and modify all traffic including passwords, session tokens, and sensitive data.",
                remediation="Configure the web server to use HTTPS with a valid TLS certificate. Consider using Let's Encrypt for free certificates."
            ))
        else:
            # Analyze TLS certificate and version
            cert_findings = await cls._analyze_certificate(parsed.hostname, parsed.port or 443)
            findings.extend(cert_findings)
            
            # Check TLS version
            tls_findings = await cls._analyze_tls_version(parsed.hostname, parsed.port or 443)
            findings.extend(tls_findings)

        # Check for HTTPS redirect
        if parsed.scheme == "http":
            redirect_finding = await cls._check_https_redirect(url)
            if redirect_finding:
                findings.append(redirect_finding)

        return findings

    @classmethod
    async def _analyze_tls_version(cls, hostname: str, port: int) -> List[Finding]:
        """Analyze TLS version used by the server."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get the negotiated TLS version
                    tls_version = ssock.version()
                    
                    # Check for weak TLS versions
                    if tls_version in ("TLSv1", "TLSv1.0"):
                        findings.append(Finding(
                            category="Transport Security",
                            title="Weak TLS Version (TLS 1.0)",
                            severity=Severity.HIGH,
                            owasp=OWASP.A02_CRYPTO_FAILURES,
                            description="The server supports TLS 1.0, which has known vulnerabilities including BEAST and POODLE attacks.",
                            impact="Attackers can potentially decrypt encrypted traffic using known cryptographic weaknesses in TLS 1.0.",
                            remediation="Disable TLS 1.0 and 1.1. Configure the server to use TLS 1.2 or TLS 1.3 only."
                        ))
                    elif tls_version == "TLSv1.1":
                        findings.append(Finding(
                            category="Transport Security",
                            title="Weak TLS Version (TLS 1.1)",
                            severity=Severity.MEDIUM,
                            owasp=OWASP.A02_CRYPTO_FAILURES,
                            description="The server supports TLS 1.1, which is deprecated and considered weak by modern standards.",
                            impact="TLS 1.1 lacks modern security features and may be vulnerable to certain attacks. Major browsers have deprecated support.",
                            remediation="Disable TLS 1.1 and configure the server to use TLS 1.2 or TLS 1.3 only."
                        ))

        except Exception:
            # Don't report errors for TLS version check
            pass

        return findings

    @classmethod
    async def _analyze_certificate(cls, hostname: str, port: int) -> List[Finding]:
        """Analyze TLS certificate details including chain validation."""
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
                                    owasp=OWASP.A02_CRYPTO_FAILURES,
                                    description=f"The TLS certificate expired on {not_after}. Expired certificates cause browser warnings and indicate potential security issues.",
                                    impact="Users will see security warnings and may be vulnerable to man-in-the-middle attacks if they bypass the warning.",
                                    remediation="Renew the TLS certificate immediately. Consider setting up automated certificate renewal."
                                ))
                            elif (expiry - now).days < 30:
                                days_left = (expiry - now).days
                                findings.append(Finding(
                                    category="Transport Security",
                                    title="TLS Certificate Expiring Soon",
                                    severity=Severity.MEDIUM,
                                    owasp=OWASP.A02_CRYPTO_FAILURES,
                                    description=f"The TLS certificate will expire on {not_after} ({days_left} days remaining). Plan for certificate renewal.",
                                    impact="If the certificate expires, users will see security warnings and may lose trust in the site.",
                                    remediation="Renew the TLS certificate before expiration. Consider using automated renewal with Let's Encrypt."
                                ))

                        # Check issuer for self-signed
                        issuer = cert.get("issuer")
                        if issuer:
                            issuer_dict = dict(x[0] for x in issuer)
                            
                            # Self-signed certificate detection
                            subject = cert.get("subject")
                            if subject:
                                subject_dict = dict(x[0] for x in subject)
                                if issuer_dict == subject_dict:
                                    findings.append(Finding(
                                        category="Transport Security",
                                        title="Self-Signed TLS Certificate",
                                        severity=Severity.HIGH,
                                        owasp=OWASP.A02_CRYPTO_FAILURES,
                                        description="The TLS certificate appears to be self-signed. Self-signed certificates are not trusted by browsers and can expose users to man-in-the-middle attacks.",
                                        impact="Users will see untrusted certificate warnings. If users bypass these warnings, they cannot verify the server's identity.",
                                        remediation="Obtain a certificate from a trusted Certificate Authority (CA). Let's Encrypt provides free trusted certificates."
                                    ))

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                category="Transport Security",
                title="Invalid TLS Certificate",
                severity=Severity.HIGH,
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description=f"The TLS certificate failed verification: {str(e)}. This may indicate a misconfigured or compromised certificate.",
                impact="Certificate verification failure means the server's identity cannot be confirmed, exposing users to potential man-in-the-middle attacks.",
                remediation="Ensure the certificate is issued by a trusted CA, is not expired, and matches the hostname."
            ))
        except ssl.SSLError as e:
            findings.append(Finding(
                category="Transport Security",
                title="TLS Connection Error",
                severity=Severity.MEDIUM,
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description=f"Could not establish secure TLS connection: {str(e)}",
                impact="TLS configuration issues may prevent secure connections or expose users to downgrade attacks.",
                remediation="Review TLS configuration and ensure modern cipher suites are enabled."
            ))
        except socket.timeout:
            findings.append(Finding(
                category="Transport Security",
                title="TLS Connection Timeout",
                severity=Severity.LOW,
                owasp=OWASP.A02_CRYPTO_FAILURES,
                description="Connection timed out while attempting to verify TLS certificate.",
                impact="Unable to verify certificate status. This may be a temporary network issue.",
                remediation="Verify the server is accessible and TLS is properly configured."
            ))
        except Exception:
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
                            owasp=OWASP.A02_CRYPTO_FAILURES,
                            description="The server redirects HTTP traffic to HTTPS. This is good practice, but users may still be vulnerable during the initial HTTP request.",
                            impact="The initial HTTP request before redirect can be intercepted, potentially exposing cookies or allowing injection of malicious content.",
                            remediation="Implement HSTS (HTTP Strict Transport Security) to ensure browsers always use HTTPS."
                        )
                
                return Finding(
                    category="Transport Security",
                    title="No HTTP to HTTPS Redirect",
                    severity=Severity.MEDIUM,
                    owasp=OWASP.A02_CRYPTO_FAILURES,
                    description="The HTTP version of the site does not redirect to HTTPS. Users accessing the site via HTTP will have unencrypted connections.",
                    impact="Users who access the site via HTTP will transmit data unencrypted, exposing sensitive information to network attackers.",
                    remediation="Configure the server to redirect all HTTP traffic to HTTPS using a 301 redirect."
                )
        except Exception:
            return None

