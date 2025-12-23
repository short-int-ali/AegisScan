"""Public Exposure Checker Module

Checks for commonly exposed files and paths.
Only checks predefined endpoints - no fuzzing or crawling.
"""

from typing import List
from urllib.parse import urljoin
import httpx

from backend.models import Finding, Severity


class ExposureChecker:
    """Checks for publicly exposed sensitive files and paths."""

    # Predefined paths to check (per requirements - NO fuzzing)
    PATHS_TO_CHECK = [
        {
            "path": "/robots.txt",
            "name": "Robots.txt",
            "description": "robots.txt file is accessible",
            "severity": Severity.LOW,
            "is_sensitive": False,
        },
        {
            "path": "/sitemap.xml",
            "name": "Sitemap.xml",
            "description": "sitemap.xml file is accessible",
            "severity": Severity.LOW,
            "is_sensitive": False,
        },
        {
            "path": "/admin",
            "name": "Admin Panel",
            "description": "An admin panel path is accessible",
            "severity": Severity.MEDIUM,
            "is_sensitive": True,
        },
        {
            "path": "/.env",
            "name": "Environment File",
            "description": "A .env file is publicly accessible, potentially exposing sensitive configuration",
            "severity": Severity.HIGH,
            "is_sensitive": True,
        },
    ]

    @classmethod
    async def analyze(cls, base_url: str, client: httpx.AsyncClient) -> List[Finding]:
        """
        Check for exposed files and paths.

        Args:
            base_url: The base URL to check
            client: HTTP client to use

        Returns:
            List of security findings
        """
        findings = []

        for path_config in cls.PATHS_TO_CHECK:
            finding = await cls._check_path(base_url, path_config, client)
            if finding:
                findings.append(finding)

        return findings

    @classmethod
    async def _check_path(
        cls, base_url: str, path_config: dict, client: httpx.AsyncClient
    ) -> Finding | None:
        """Check a single path for accessibility."""
        full_url = urljoin(base_url, path_config["path"])

        try:
            response = await client.get(full_url, timeout=10, follow_redirects=True)
            status_code = response.status_code

            # Only report if resource exists (2xx status)
            if 200 <= status_code < 300:
                if path_config["is_sensitive"]:
                    return Finding(
                        category="Public Exposure",
                        title=f"{path_config['name']} Exposed",
                        severity=path_config["severity"],
                        description=f"{path_config['description']}. URL: {full_url} returned status {status_code}.",
                        remediation=cls._get_remediation(path_config["path"])
                    )
                else:
                    # For non-sensitive files like robots.txt, just note their presence
                    return Finding(
                        category="Public Exposure",
                        title=f"{path_config['name']} Found",
                        severity=Severity.LOW,
                        description=f"{path_config['description']}. This is typically expected but may reveal information about site structure.",
                        remediation="Review the contents to ensure no sensitive paths or information are exposed."
                    )

            # For admin paths, also report if it returns a login page (often 401/403)
            if path_config["path"] == "/admin" and status_code in (401, 403):
                return Finding(
                    category="Public Exposure",
                    title="Admin Panel Detected",
                    severity=Severity.LOW,
                    description=f"An admin panel appears to exist at {full_url} (returned {status_code}). While access is restricted, the presence of an admin panel is now known.",
                    remediation="Consider hiding admin panels behind non-obvious URLs or implementing IP-based access controls."
                )

        except httpx.TimeoutException:
            # Don't report timeouts
            pass
        except Exception:
            # Don't report other errors
            pass

        return None

    @classmethod
    def _get_remediation(cls, path: str) -> str:
        """Get specific remediation advice for a path."""
        remediations = {
            "/admin": "Restrict admin panel access using authentication, IP whitelisting, or move it to a non-standard URL.",
            "/.env": "Immediately remove or restrict access to the .env file. Review and rotate any exposed credentials. Configure the web server to deny access to dotfiles.",
            "/robots.txt": "Review robots.txt contents to ensure sensitive paths are not disclosed.",
            "/sitemap.xml": "Review sitemap.xml to ensure no sensitive URLs are exposed.",
        }
        return remediations.get(path, "Restrict access to this resource or remove it if not needed.")

