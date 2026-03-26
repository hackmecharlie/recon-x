# ============================================================
# RECON-X | modules/web/header_scanner.py
# Description: Async HTTP header security scanner — checks for
#              missing security headers and info-disclosing headers
# ============================================================

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx

from engine.findings import Finding

logger = logging.getLogger(__name__)


@dataclass
class HeaderScanResult:
    """Results from HTTP header security analysis."""
    host: str
    scheme: str
    port: int
    url: str
    status_code: Optional[int] = None
    all_headers: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    headers_summary: Dict[str, Dict[str, str]] = field(default_factory=dict)


# (header_name, severity, description, remediation_hint)
_REQUIRED_HEADERS: List[Tuple[str, str, str, str]] = [
    (
        "Content-Security-Policy",
        "Medium",
        "Content-Security-Policy (CSP) header is missing. CSP mitigates XSS and data injection attacks.",
        "Add a Content-Security-Policy header: Content-Security-Policy: default-src 'self'; script-src 'self'",
    ),
    (
        "X-Content-Type-Options",
        "Low",
        "X-Content-Type-Options header is missing. Without this, browsers may MIME-sniff responses, enabling XSS in certain scenarios.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "X-Frame-Options",
        "Medium",
        "X-Frame-Options header is missing. The page may be embeddable in iframes, enabling clickjacking.",
        "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
    ),
    (
        "Referrer-Policy",
        "Low",
        "Referrer-Policy header is missing. Sensitive URL parameters may leak in the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        "Low",
        "Permissions-Policy header is missing. Browser features like camera/microphone/geolocation are unrestricted.",
        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
]

# (header_name, severity, description)
_DISCLOSURE_HEADERS: List[Tuple[str, str, str]] = [
    ("Server", "Low", "Server header discloses web server software and version, aiding fingerprinting."),
    ("X-Powered-By", "Low", "X-Powered-By header discloses backend technology (e.g., PHP version)."),
    ("X-AspNet-Version", "Low", "X-AspNet-Version discloses the exact ASP.NET version."),
    ("X-AspNetMvc-Version", "Low", "X-AspNetMvc-Version discloses the ASP.NET MVC version."),
    ("X-Generator", "Low", "X-Generator discloses the CMS or framework generating the response."),
    ("X-Drupal-Cache", "Informational", "X-Drupal-Cache indicates this is a Drupal site."),
    ("Via", "Informational", "Via header reveals intermediate proxy/CDN infrastructure."),
    ("X-CF-Powered-By", "Informational", "X-CF-Powered-By discloses ColdFusion usage."),
    ("X-OWA-Version", "Low", "X-OWA-Version discloses the Outlook Web Access version."),
]

# Headers to include in security summary (name, category, description)
_SECURITY_HEADERS_SUMMARY: List[Tuple[str, str, str]] = [
    # Security Headers
    ("Content-Security-Policy", "Security", "Prevents XSS and data injection attacks"),
    ("X-Content-Type-Options", "Security", "Prevents MIME type sniffing"),
    ("X-Frame-Options", "Security", "Prevents clickjacking attacks"),
    ("X-XSS-Protection", "Security", "Enables XSS filtering in browsers"),
    ("Strict-Transport-Security", "Security", "Enforces HTTPS connections"),
    ("Referrer-Policy", "Security", "Controls referrer information leakage"),
    ("Permissions-Policy", "Security", "Restricts browser features (camera, microphone, etc.)"),
    ("Cross-Origin-Embedder-Policy", "Security", "Enables cross-origin isolation"),
    ("Cross-Origin-Opener-Policy", "Security", "Isolates origins from each other"),
    ("Cross-Origin-Resource-Policy", "Security", "Controls cross-origin resource access"),

    # Information Disclosure Headers
    ("Server", "Information", "Web server software and version"),
    ("X-Powered-By", "Information", "Backend technology information"),
    ("X-AspNet-Version", "Information", "ASP.NET version disclosure"),
    ("X-AspNetMvc-Version", "Information", "ASP.NET MVC version disclosure"),
    ("X-Generator", "Information", "CMS/framework information"),

    # Caching and Performance
    ("Cache-Control", "Performance", "Caching directives"),
    ("Expires", "Performance", "Cache expiration date"),

    # Cookies and Sessions
    ("Set-Cookie", "Session", "Session and cookie settings"),

    # Other Common Headers
    ("Content-Type", "General", "Response content type"),
    ("Content-Length", "General", "Response body length"),
    ("Last-Modified", "General", "Last modification date"),
    ("ETag", "General", "Entity tag for caching"),
]


class HeaderScanner:
    """Scan HTTP response headers for security issues.

    Checks for missing security headers and information-disclosing
    headers across both HTTP and HTTPS.
    """

    def __init__(
        self,
        scheme: str,
        host: str,
        port: Optional[int] = None,
        timeout: int = 15,
        user_agent: str = "Mozilla/5.0 (compatible; RECON-X/1.0; Security Scanner)",
    ) -> None:
        """Initialize HeaderScanner.

        Args:
            scheme: 'http' or 'https'.
            host: Target hostname or IP.
            port: Optional port override.
            timeout: Request timeout in seconds.
            user_agent: User-Agent string to send.
        """
        self.scheme = scheme.lower()
        self.host = host
        self.timeout = timeout
        self.user_agent = user_agent

        if port:
            self.port = port
        else:
            self.port = 443 if self.scheme == "https" else 80

        port_suffix = ""
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            port_suffix = f":{self.port}"
        self.base_url = f"{self.scheme}://{self.host}{port_suffix}"

    async def scan(self) -> HeaderScanResult:
        """Fetch the target and analyze response headers.

        Returns:
            HeaderScanResult with all headers and security findings.
        """
        result = HeaderScanResult(
            host=self.host,
            scheme=self.scheme,
            port=self.port,
            url=self.base_url,
        )

        headers_dict: Dict[str, str] = {}
        status_code: Optional[int] = None

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            ) as client:
                response = await client.get(self.base_url + "/")
                status_code = response.status_code
                headers_dict = {k.lower(): v for k, v in response.headers.items()}
        except httpx.ConnectError as exc:
            logger.debug("Connect failed for %s: %s", self.base_url, exc)
            return result
        except httpx.TimeoutException as exc:
            logger.debug("Timeout for %s: %s", self.base_url, exc)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.debug("Header scan failed for %s: %s", self.base_url, exc)
            return result

        result.status_code = status_code
        result.all_headers = headers_dict
        result.findings = self._generate_findings(headers_dict)
        result.headers_summary = self._generate_security_summary(headers_dict)
        return result

    def _generate_findings(self, headers: Dict[str, str]) -> List[Finding]:
        """Generate security findings from the response headers.

        Args:
            headers: Lowercase-keyed response headers dict.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []

        # Check for missing required security headers
        for header_name, severity, description, remediation in _REQUIRED_HEADERS:
            header_lower = header_name.lower()

            # HSTS is only relevant for HTTPS
            if header_lower == "strict-transport-security" and self.scheme != "https":
                continue

            if header_lower not in headers:
                findings.append(Finding(
                    title=f"{header_name} Header Missing",
                    severity=severity,  # type: ignore[arg-type]
                    category="Web Headers",
                    target=self.host,
                    port=self.port,
                    description=description,
                    evidence=f"GET {self.base_url}/\nResponse missing header: {header_name}",
                    remediation=remediation,
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/",
                    ],
                ))

        # Check for X-Frame-Options issues (beyond just missing)
        xfo = headers.get("x-frame-options", "")
        if xfo.upper() == "ALLOWALL":
            findings.append(Finding(
                title="X-Frame-Options Set to ALLOWALL",
                severity="High",
                category="Web Headers",
                target=self.host,
                port=self.port,
                description="X-Frame-Options is set to ALLOWALL, which explicitly permits embedding from any origin. This defeats clickjacking protection entirely.",
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Change to: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
                cvss_score=7.4,
            ))

        # Check for information-disclosing headers
        for header_name, severity, description in _DISCLOSURE_HEADERS:
            header_lower = header_name.lower()
            if header_lower in headers:
                value = headers[header_lower]
                findings.append(Finding(
                    title=f"{header_name} Header Disclosed",
                    severity=severity,  # type: ignore[arg-type]
                    category="Web Headers",
                    target=self.host,
                    port=self.port,
                    description=f"{description} Value: '{value}'",
                    evidence=f"{header_name}: {value}\n(from {self.base_url})",
                    remediation=f"Remove or suppress the {header_name} header from server responses.",
                    cvss_score=3.1 if severity == "Low" else 0.0,
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))

        # Cache-Control on root path (informational check)
        cache_ctrl = headers.get("cache-control", "")
        if not cache_ctrl or "no-store" not in cache_ctrl.lower():
            findings.append(Finding(
                title="Cache-Control Not Restrictive",
                severity="Low",
                category="Web Headers",
                target=self.host,
                port=self.port,
                description="Cache-Control header is missing 'no-store' directive. Sensitive responses may be cached by intermediaries.",
                evidence=f"Cache-Control: {cache_ctrl or '(not set)'}",
                remediation="For sensitive pages, set: Cache-Control: no-store, no-cache, private",
                cvss_score=2.0,
            ))

        return findings

    def _generate_security_summary(self, headers: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """Generate a comprehensive summary of security-related headers.

        Args:
            headers: Lowercase-keyed response headers dict.

        Returns:
            Dict categorized by header type with status and values.
        """
        summary: Dict[str, Dict[str, str]] = {}

        for header_name, category, description in _SECURITY_HEADERS_SUMMARY:
            header_lower = header_name.lower()
            status = "Present" if header_lower in headers else "Missing"
            value = headers.get(header_lower, "")

            # Special handling for certain headers
            if header_lower == "set-cookie" and value:
                # For cookies, show if they're secure/httponly
                cookies = value.split(";")
                flags = []
                if any("secure" in c.lower() for c in cookies):
                    flags.append("Secure")
                if any("httponly" in c.lower() for c in cookies):
                    flags.append("HttpOnly")
                if any("samesite" in c.lower() for c in cookies):
                    flags.append("SameSite")
                if flags:
                    value = f"{value[:50]}... (Flags: {', '.join(flags)})"
                else:
                    value = f"{value[:50]}... (No security flags)"

            elif header_lower == "cache-control" and value:
                # Check for security-relevant cache directives
                directives = [d.strip().lower() for d in value.split(",")]
                security_directives = []
                if "no-store" in directives:
                    security_directives.append("no-store")
                if "no-cache" in directives:
                    security_directives.append("no-cache")
                if "private" in directives:
                    security_directives.append("private")
                if security_directives:
                    value = f"{value} (Security: {', '.join(security_directives)})"
                else:
                    value = f"{value} (No security directives)"

            elif header_lower == "strict-transport-security" and value:
                # Parse HSTS max-age
                if "max-age=" in value.lower():
                    try:
                        max_age_part = [p for p in value.split(";") if "max-age=" in p.lower()][0]
                        max_age = int(max_age_part.split("=")[1])
                        days = max_age // 86400
                        value = f"{value} ({days} days)"
                    except (ValueError, IndexError):
                        pass

            summary[header_name] = {
                "category": category,
                "description": description,
                "status": status,
                "value": value[:100] + ("..." if len(value) > 100 else ""),
            }

        return summary
