"""URL Normalization Module

Validates and normalizes URLs for safe scanning.
Rejects private/internal IPs to prevent SSRF.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional


class URLNormalizer:
    """Handles URL validation and normalization."""

    # Private IP ranges that should be blocked
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    @classmethod
    def normalize(cls, url: str) -> Tuple[bool, str, Optional[str]]:
        """
        Normalize and validate a URL.

        Args:
            url: The URL to normalize

        Returns:
            Tuple of (is_valid, normalized_url_or_error, error_message)
        """
        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, "", f"Invalid URL format: {str(e)}"

        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            return False, "", "Only HTTP and HTTPS schemes are supported"

        # Validate hostname exists
        if not parsed.netloc:
            return False, "", "No hostname provided"

        hostname = parsed.hostname
        if not hostname:
            return False, "", "Invalid hostname"

        # Check for private/internal IPs
        is_private, error = cls._is_private_host(hostname)
        if is_private:
            return False, "", error

        # Reconstruct normalized URL
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        if parsed.path:
            normalized += parsed.path
        if parsed.query:
            normalized += f"?{parsed.query}"

        return True, normalized, None

    @classmethod
    def _is_private_host(cls, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Check if hostname resolves to a private IP.

        Args:
            hostname: The hostname to check

        Returns:
            Tuple of (is_private, error_message)
        """
        try:
            # Try to parse as IP address directly
            try:
                ip = ipaddress.ip_address(hostname)
                if cls._is_private_ip(ip):
                    return True, "Scanning private/internal IP addresses is not allowed"
                return False, None
            except ValueError:
                pass

            # Resolve hostname to IP
            try:
                ip_str = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(ip_str)
                if cls._is_private_ip(ip):
                    return True, "Target resolves to a private/internal IP address"
            except socket.gaierror:
                return True, f"Could not resolve hostname: {hostname}"

            return False, None

        except Exception as e:
            return True, f"Error validating hostname: {str(e)}"

    @classmethod
    def _is_private_ip(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if an IP address is in a private range."""
        for network in cls.PRIVATE_RANGES:
            try:
                if ip in network:
                    return True
            except TypeError:
                # IPv4/IPv6 mismatch, skip
                continue
        return False

