# ============================================================
# RECON-X | modules/web/clickjack.py
# Description: Detect clickjacking vulnerability by checking
#              X-Frame-Options and CSP frame-ancestors directives
# ============================================================

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from engine.findings import Finding

logger = logging.getLogger(__name__)


@dataclass
class ClickjackResult:
    """Results from clickjacking protection analysis."""
    host: str
    scheme: str
    xfo_header: Optional[str] = None
    csp_header: Optional[str] = None
    frame_ancestors: Optional[str] = None
    protected: bool = False
    findings: List[Finding] = field(default_factory=list)


class ClickjackChecker:
    """Check clickjacking protections via X-Frame-Options and CSP.

    A page is considered protected if it has either:
    - X-Frame-Options: DENY or SAMEORIGIN
    - Content-Security-Policy with a frame-ancestors directive that
      restricts framing.
    """

    def __init__(
        self,
        scheme: str,
        host: str,
        port: Optional[int] = None,
        timeout: int = 10,
    ) -> None:
        """Initialize ClickjackChecker.

        Args:
            scheme: 'http' or 'https'.
            host: Target hostname or IP.
            port: Optional port override.
            timeout: Request timeout in seconds.
        """
        self.scheme = scheme.lower()
        self.host = host
        self.timeout = timeout
        self.port = port or (443 if scheme == "https" else 80)
        port_suffix = ""
        if (self.scheme == "https" and self.port != 443) or (self.scheme == "http" and self.port != 80):
            port_suffix = f":{self.port}"
        self.base_url = f"{self.scheme}://{self.host}{port_suffix}"

    async def check(self) -> ClickjackResult:
        """Perform clickjacking protection check.

        Returns:
            ClickjackResult with analysis and findings.
        """
        result = ClickjackResult(host=self.host, scheme=self.scheme)

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=self.timeout,
            ) as client:
                response = await client.get(self.base_url + "/")
                headers = {k.lower(): v for k, v in response.headers.items()}

                xfo = headers.get("x-frame-options", "")
                csp = headers.get("content-security-policy", "")
                result.xfo_header = xfo or None
                result.csp_header = csp or None

                # Extract frame-ancestors from CSP
                if csp:
                    for directive in csp.split(";"):
                        directive = directive.strip()
                        if directive.lower().startswith("frame-ancestors"):
                            result.frame_ancestors = directive
                            break

                result.protected = self._is_protected(xfo, result.frame_ancestors)
                result.findings = self._generate_findings(result)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Clickjack check failed for %s: %s", self.base_url, exc)

        return result

    @staticmethod
    def _is_protected(xfo: str, frame_ancestors: Optional[str]) -> bool:
        """Determine if the page is protected against clickjacking.

        Args:
            xfo: X-Frame-Options header value.
            frame_ancestors: CSP frame-ancestors directive value if present.

        Returns:
            True if adequately protected.
        """
        xfo_upper = xfo.upper().strip()

        # Strong XFO values
        if xfo_upper in ("DENY", "SAMEORIGIN"):
            return True

        # CSP frame-ancestors that restricts framing
        if frame_ancestors:
            fa_lower = frame_ancestors.lower()
            # 'none' or 'self' are protective
            if "'none'" in fa_lower or "'self'" in fa_lower:
                return True

        return False

    def _generate_findings(self, result: ClickjackResult) -> List[Finding]:
        """Generate clickjacking-related findings.

        Args:
            result: Populated ClickjackResult.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []

        if result.protected:
            return findings  # No issues

        xfo = result.xfo_header or ""
        xfo_upper = xfo.upper().strip()

        # Case: ALLOWALL explicitly set
        if xfo_upper == "ALLOWALL":
            findings.append(Finding(
                title="X-Frame-Options Set to ALLOWALL",
                severity="High",
                category="Web Headers",
                target=self.host,
                port=self.port,
                description=(
                    "X-Frame-Options is set to ALLOWALL, which explicitly grants permission "
                    "to embed this page in an iframe from any origin. This actively enables clickjacking."
                ),
                evidence=f"X-Frame-Options: {xfo}\nCSP frame-ancestors: {result.frame_ancestors or 'not set'}\nURL: {self.base_url}",
                remediation="Change to: X-Frame-Options: DENY  or use CSP: frame-ancestors 'none'",
                cvss_score=7.4,
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
            ))
            return findings

        # Case: ALLOW-FROM (deprecated, potentially weak)
        if xfo_upper.startswith("ALLOW-FROM"):
            findings.append(Finding(
                title="X-Frame-Options Using Deprecated ALLOW-FROM",
                severity="Low",
                category="Web Headers",
                target=self.host,
                port=self.port,
                description=(
                    f"X-Frame-Options uses the deprecated ALLOW-FROM directive ({xfo}). "
                    "This directive is not supported by modern browsers and may not provide clickjacking protection."
                ),
                evidence=f"X-Frame-Options: {xfo}\nURL: {self.base_url}",
                remediation="Replace with Content-Security-Policy: frame-ancestors directive, which has modern browser support.",
                cvss_score=3.1,
            ))
            return findings

        # Case: Neither XFO nor CSP frame-ancestors present
        findings.append(Finding(
            title="Clickjacking Protection Missing",
            severity="Medium",
            category="Web Headers",
            target=self.host,
            port=self.port,
            description=(
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was found. "
                "This page can be embedded in an iframe from any origin, enabling clickjacking attacks."
            ),
            evidence=(
                f"X-Frame-Options: {xfo or '(not set)'}\n"
                f"CSP frame-ancestors: {result.frame_ancestors or '(not set)'}\n"
                f"URL: {self.base_url}"
            ),
            remediation=(
                "Add one of the following to all HTTP responses:\n"
                "  X-Frame-Options: DENY\n"
                "  Content-Security-Policy: frame-ancestors 'none'\n"
                "Use the CSP approach for modern browser coverage."
            ),
            cvss_score=5.4,
            references=[
                "https://owasp.org/www-community/attacks/Clickjacking",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ],
        ))

        return findings
