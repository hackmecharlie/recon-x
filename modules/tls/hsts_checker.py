# ============================================================
# RECON-X | modules/tls/hsts_checker.py
# Description: Check HTTP Strict Transport Security headers,
#              max-age values, directives, and preload list status
# ============================================================

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from engine.findings import Finding

logger = logging.getLogger(__name__)

_HSTSPRELOAD_API = "https://hstspreload.org/api/v2/status?domain={domain}"
_MIN_RECOMMENDED_MAX_AGE = 31536000  # 1 year in seconds


@dataclass
class HSTSResult:
    """Results from HSTS header analysis."""
    host: str
    hsts_present: bool = False
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    preload_list_status: Optional[str] = None
    raw_header: str = ""
    findings: List[Finding] = field(default_factory=list)


class HSTSChecker:
    """Check Strict-Transport-Security headers for correct configuration.

    Tests both HTTP and HTTPS responses, validates max-age,
    subdomains directive, preload status, and hstspreload.org listing.
    """

    def __init__(self, host: str, port: int = 443, timeout: int = 10) -> None:
        """Initialize HSTSChecker.

        Args:
            host: Target hostname or IP.
            port: HTTPS port (default 443).
            timeout: HTTP request timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    async def check(self) -> HSTSResult:
        """Perform all HSTS checks.

        Returns:
            HSTSResult with header analysis and findings.
        """
        result = HSTSResult(host=self.host)
        port_suffix = f":{self.port}" if self.port not in (443, 80) else ""
        https_url = f"https://{self.host}{port_suffix}/"
        http_url = f"http://{self.host}/"

        # Check HTTPS response for HSTS header
        https_headers = await self._fetch_headers(https_url)
        hsts_header = self._find_hsts_header(https_headers)

        if hsts_header:
            result.hsts_present = True
            result.raw_header = hsts_header
            self._parse_hsts_directives(hsts_header, result)
        else:
            result.hsts_present = False

        # Check preload list status (best-effort)
        if "." in self.host:
            result.preload_list_status = await self._check_preload_status(self.host)

        result.findings = self._generate_findings(result)
        return result

    async def _fetch_headers(self, url: str) -> dict:
        """Fetch HTTP response headers from a URL.

        Args:
            url: Full URL to request.

        Returns:
            Dict of response headers, empty dict on failure.
        """
        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=self.timeout,
            ) as client:
                response = await client.get(url)
                return dict(response.headers)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to fetch %s: %s", url, exc)
            return {}

    @staticmethod
    def _find_hsts_header(headers: dict) -> Optional[str]:
        """Find the HSTS header value in a headers dict (case-insensitive).

        Args:
            headers: Dict of HTTP response headers.

        Returns:
            HSTS header value string, or None if not present.
        """
        for key, value in headers.items():
            if key.lower() == "strict-transport-security":
                return value
        return None

    @staticmethod
    def _parse_hsts_directives(header_value: str, result: HSTSResult) -> None:
        """Parse HSTS header directives into HSTSResult fields.

        Args:
            header_value: Raw Strict-Transport-Security header value.
            result: HSTSResult to populate in-place.
        """
        parts = [p.strip().lower() for p in header_value.split(";")]
        for part in parts:
            if part.startswith("max-age="):
                try:
                    result.max_age = int(part.split("=", 1)[1].strip())
                except ValueError:
                    result.max_age = 0
            elif part == "includesubdomains":
                result.include_subdomains = True
            elif part == "preload":
                result.preload = True

    async def _check_preload_status(self, domain: str) -> str:
        """Query hstspreload.org API for preload status.

        Args:
            domain: Domain name to check.

        Returns:
            Status string: 'preloaded', 'pending', 'unknown', or 'error'.
        """
        try:
            url = _HSTSPRELOAD_API.format(domain=domain)
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url)
                data = response.json()
                status = data.get("status", "unknown")
                return status
        except Exception as exc:  # noqa: BLE001
            logger.debug("hstspreload.org check failed for %s: %s", domain, exc)
            return "unknown"

    def _generate_findings(self, result: HSTSResult) -> List[Finding]:
        """Generate HSTS-related security findings.

        Args:
            result: Populated HSTSResult.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []
        target_str = self.host

        if not result.hsts_present:
            findings.append(Finding(
                title="HSTS Header Missing",
                severity="Medium",
                category="TLS",
                target=target_str,
                port=self.port,
                description=(
                    "The Strict-Transport-Security (HSTS) header is absent from the HTTPS response. "
                    "Without HSTS, users can be downgraded to HTTP via SSL stripping attacks."
                ),
                evidence=f"No Strict-Transport-Security header found in HTTPS response from {self.host}:{self.port}",
                remediation=(
                    "Add the following header to all HTTPS responses:\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ),
                cvss_score=5.4,
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            ))
        else:
            # Check max-age value
            if result.max_age is not None and result.max_age < _MIN_RECOMMENDED_MAX_AGE:
                findings.append(Finding(
                    title="HSTS max-age Too Short",
                    severity="Low",
                    category="TLS",
                    target=target_str,
                    port=self.port,
                    description=(
                        f"HSTS max-age is set to {result.max_age} seconds "
                        f"({result.max_age // 86400} days), which is below the recommended minimum "
                        f"of {_MIN_RECOMMENDED_MAX_AGE} seconds (1 year)."
                    ),
                    evidence=f"Strict-Transport-Security: {result.raw_header}",
                    remediation=(
                        f"Increase max-age to at least {_MIN_RECOMMENDED_MAX_AGE} (1 year):\n"
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    cvss_score=3.1,
                    references=["https://hstspreload.org/"],
                ))

            # Check for missing includeSubDomains
            if not result.include_subdomains:
                findings.append(Finding(
                    title="HSTS Missing includeSubDomains",
                    severity="Informational",
                    category="TLS",
                    target=target_str,
                    port=self.port,
                    description="The HSTS header does not include the 'includeSubDomains' directive, leaving subdomains potentially unprotected.",
                    evidence=f"Strict-Transport-Security: {result.raw_header}",
                    remediation="Add 'includeSubDomains' to the HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    cvss_score=0.0,
                ))

        return findings
