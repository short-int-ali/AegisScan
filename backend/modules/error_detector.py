"""Error Verbosity Detection Module

Detects verbose error messages, stack traces, and debug information
in normal responses (passive detection only - no error triggering).
"""

import re
from typing import List, Tuple
import httpx

from models import Finding, Severity, OWASP


class ErrorVerbosityDetector:
    """Detects verbose error messages and debug information in responses."""

    # Patterns for common error/debug signatures
    ERROR_PATTERNS: List[Tuple[str, str, str]] = [
        # Stack traces
        (r'Traceback \(most recent call last\)', "Python Stack Trace", "Python"),
        (r'at [a-zA-Z0-9_.$]+\([^)]*\)\s*\n\s*at', "Java/JavaScript Stack Trace", "Java/JS"),
        (r'System\.NullReferenceException|System\.[A-Z][a-zA-Z]+Exception', ".NET Exception", ".NET"),
        (r'#\d+\s+[\w\\/:]+\.php\(\d+\)', "PHP Stack Trace", "PHP"),
        (r'Fatal error:.*in\s+[\w\\/:]+\.php\s+on\s+line\s+\d+', "PHP Fatal Error", "PHP"),
        (r'Parse error:.*in\s+[\w\\/:]+\.php\s+on\s+line\s+\d+', "PHP Parse Error", "PHP"),
        (r'Warning:.*in\s+[\w\\/:]+\.php\s+on\s+line\s+\d+', "PHP Warning", "PHP"),
        (r'Notice:.*in\s+[\w\\/:]+\.php\s+on\s+line\s+\d+', "PHP Notice", "PHP"),
        
        # Database errors
        (r'mysql_|mysqli_|PDOException|pg_|sqlite_', "Database Error Reference", "Database"),
        (r'ORA-\d{5}', "Oracle Database Error", "Oracle"),
        (r'SQLSTATE\[', "SQL State Error", "Database"),
        (r'You have an error in your SQL syntax', "MySQL Syntax Error", "MySQL"),
        (r'PostgreSQL.*ERROR:', "PostgreSQL Error", "PostgreSQL"),
        
        # Framework debug info
        (r'Django Debug Mode|DEBUG = True', "Django Debug Mode", "Django"),
        (r'Rails\.env\s*=\s*["\']development["\']', "Rails Development Mode", "Rails"),
        (r'<h1>Whoops, looks like something went wrong\.</h1>', "Laravel Debug Page", "Laravel"),
        (r'WP_DEBUG', "WordPress Debug Mode", "WordPress"),
        
        # ASP.NET specific
        (r'Server Error in.*Application', "ASP.NET Server Error", "ASP.NET"),
        (r'<title>.*Error</title>.*<h2>.*<i>.*Exception', "ASP.NET Exception Page", "ASP.NET"),
        (r'YSOD|Yellow Screen of Death', "ASP.NET Error Page", "ASP.NET"),
        
        # Apache/Nginx errors
        (r'<address>Apache/[\d.]+ .*Server at', "Apache Server Error", "Apache"),
        (r'nginx/[\d.]+</center>', "Nginx Server Error", "Nginx"),
        
        # Generic debug info
        (r'var_dump\(|print_r\(', "PHP Debug Output", "PHP"),
        (r'console\.log\s*\([^)]*debug', "JavaScript Debug Log", "JavaScript"),
        (r'DEBUG|DEVELOPMENT|STAGING', "Debug Environment Indicator", "Generic"),
    ]

    # File path patterns that indicate information disclosure
    PATH_PATTERNS = [
        (r'/var/www/[^\s<"\']+', "Unix Web Path"),
        (r'/home/[^\s<"\']+', "Unix Home Path"),
        (r'C:\\[^\s<"\']+', "Windows Path"),
        (r'/usr/[^\s<"\']+\.(?:py|php|rb|js)', "Server Code Path"),
    ]

    @classmethod
    def analyze(cls, response: httpx.Response) -> List[Finding]:
        """
        Analyze response for error verbosity and debug information.

        Args:
            response: The HTTP response to analyze

        Returns:
            List of security findings
        """
        findings = []

        # Only analyze text responses
        content_type = response.headers.get("content-type", "")
        if not any(ct in content_type for ct in ["text/html", "text/plain", "application/json"]):
            return findings

        text = response.text
        
        # Track what we've found to avoid duplicates
        found_errors = set()
        found_paths = set()

        # Check for error patterns
        for pattern, error_name, technology in cls.ERROR_PATTERNS:
            if error_name in found_errors:
                continue
                
            if re.search(pattern, text, re.IGNORECASE):
                found_errors.add(error_name)

        # Check for file paths
        for pattern, path_type in cls.PATH_PATTERNS:
            if path_type in found_paths:
                continue
                
            matches = re.findall(pattern, text)
            if matches:
                found_paths.add(path_type)

        # Generate findings
        if found_errors:
            error_list = list(found_errors)[:5]
            more_count = len(found_errors) - 5 if len(found_errors) > 5 else 0
            
            description = f"Verbose error messages or debug information detected in the response. Found patterns: {', '.join(error_list)}."
            if more_count > 0:
                description += f" ({more_count} more patterns not shown)"

            findings.append(Finding(
                category="Information Disclosure",
                title="Error Verbosity Detected",
                severity=Severity.MEDIUM,
                owasp=OWASP.A05_SECURITY_MISCONFIG,
                description=description,
                impact="Verbose error messages expose internal implementation details, file paths, database structure, and technology stack. This information aids attackers in crafting targeted exploits.",
                remediation="Configure custom error pages for production. Disable debug mode and detailed error messages. Log errors server-side instead of displaying them to users."
            ))

        if found_paths:
            path_list = list(found_paths)
            
            findings.append(Finding(
                category="Information Disclosure",
                title="Server Path Disclosure",
                severity=Severity.LOW,
                owasp=OWASP.A05_SECURITY_MISCONFIG,
                description=f"Server file paths detected in the response. Path types found: {', '.join(path_list)}.",
                impact="File path disclosure reveals the server's directory structure, username patterns, and operating system. This information can aid in targeted attacks.",
                remediation="Review error handling to prevent path disclosure. Use custom error pages and avoid exposing full file paths in responses."
            ))

        return findings

