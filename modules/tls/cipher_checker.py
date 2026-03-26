# ============================================================
# RECON-X | modules/tls/cipher_checker.py
# Description: Test accepted TLS protocol versions and cipher suites
#              using sslyze, generating findings for weak configurations
# ============================================================

import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional

from engine.findings import Finding

logger = logging.getLogger(__name__)


@dataclass
class CipherCheckResult:
    """Results from TLS cipher and protocol version testing."""
    host: str
    port: int
    accepted_protocols: List[str] = field(default_factory=list)
    rejected_protocols: List[str] = field(default_factory=list)
    accepted_ciphers: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


# Protocol severity mapping
_PROTOCOL_SEVERITY = {
    "SSLv2": ("Critical", 9.0),
    "SSLv3": ("Critical", 9.0),
    "TLSv1.0": ("Medium", 5.9),
    "TLSv1.1": ("Low", 3.7),
    "TLSv1.2": None,
    "TLSv1.3": None,
}

# Cipher weakness classification
_CIPHER_ISSUES = {
    "NULL": ("NULL Cipher Accepted", "Critical", 9.5, "Cipher provides no encryption"),
    "EXPORT": ("EXPORT Cipher Accepted", "Critical", 9.1, "Export-grade cipher allows trivial decryption"),
    "aNULL": ("Anonymous Cipher Accepted", "Critical", 9.0, "No server authentication, trivially MITM-able"),
    "RC4": ("RC4 Cipher Accepted", "High", 7.4, "RC4 is cryptographically broken (RFC 7465)"),
    "DES": ("DES/3DES Cipher Accepted (SWEET32)", "High", 7.5, "3DES is vulnerable to birthday attacks"),
    "3DES": ("DES/3DES Cipher Accepted (SWEET32)", "High", 7.5, "3DES is vulnerable to SWEET32 birthday attacks"),
    "ADH": ("Anonymous DH Cipher Accepted", "Critical", 9.0, "No authentication, vulnerable to MITM"),
    "AECDH": ("Anonymous ECDH Cipher Accepted", "Critical", 9.0, "No authentication, vulnerable to MITM"),
}

# Python ssl module protocol constants
_SSL_PROTOCOLS = [
    ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "PROTOCOL_TLS_CLIENT") else None, ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
    ("TLSv1.1", None, ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
    ("TLSv1.2", None, ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None),
    ("TLSv1.3", None, ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
]


class CipherChecker:
    """Test TLS protocol versions and cipher suites for weaknesses.

    Uses sslyze when available, falls back to ssl module probing.
    """

    def __init__(self, host: str, port: int = 443, timeout: int = 10) -> None:
        """Initialize CipherChecker.

        Args:
            host: Target hostname or IP.
            port: TLS port (default 443).
            timeout: Connection timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    async def check(self) -> CipherCheckResult:
        """Run all cipher and protocol checks.

        Returns:
            CipherCheckResult with accepted protocols, ciphers, and findings.
        """
        result = CipherCheckResult(host=self.host, port=self.port)

        # Try sslyze first for comprehensive results
        sslyze_ok = await self._check_via_sslyze(result)
        if not sslyze_ok:
            # Fallback to ssl module probing
            self._check_via_ssl_module(result)

        result.findings = self._generate_findings(result)
        return result

    async def _check_via_sslyze(self, result: CipherCheckResult) -> bool:
        """Use sslyze to test protocol versions and cipher suites.

        Args:
            result: CipherCheckResult to populate in-place.

        Returns:
            True if sslyze succeeded, False if it failed/unavailable.
        """
        try:
            import asyncio
            from sslyze import (
                Scanner,
                ServerNetworkLocation,
                ServerScanRequest,
                ScanCommand,
            )
            from sslyze.errors import ServerHostnameCouldNotBeResolved, ConnectionToServerFailed

            location = ServerNetworkLocation(self.host, self.port)
            scan_request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            for scan_result in scanner.get_results():
                if scan_result.scan_result is None:
                    return False

                protocol_map = {
                    "SSLv2": ScanCommand.SSL_2_0_CIPHER_SUITES,
                    "SSLv3": ScanCommand.SSL_3_0_CIPHER_SUITES,
                    "TLSv1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
                    "TLSv1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
                    "TLSv1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
                    "TLSv1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
                }

                for proto_name, cmd in protocol_map.items():
                    try:
                        proto_result = getattr(scan_result.scan_result, cmd.value, None)
                        if proto_result is None:
                            continue
                        accepted = getattr(proto_result.result, "accepted_cipher_suites", [])
                        if accepted:
                            result.accepted_protocols.append(proto_name)
                            for cs in accepted:
                                cipher_name = getattr(cs, "cipher_suite", None)
                                if cipher_name:
                                    cn = str(cipher_name)
                                    result.accepted_ciphers.append(f"{proto_name}: {cn}")
                        else:
                            result.rejected_protocols.append(proto_name)
                    except Exception as inner_exc:  # noqa: BLE001
                        logger.debug("sslyze proto %s error: %s", proto_name, inner_exc)

            return bool(result.accepted_protocols or result.rejected_protocols)

        except ImportError:
            logger.debug("sslyze not available, using ssl fallback")
            return False
        except Exception as exc:  # noqa: BLE001
            logger.debug("sslyze failed for %s:%d: %s", self.host, self.port, exc)
            return False

    def _check_via_ssl_module(self, result: CipherCheckResult) -> None:
        """Probe TLS versions using Python's built-in ssl module.

        Args:
            result: CipherCheckResult to populate in-place.
        """
        versions_to_test = []

        if hasattr(ssl, "TLSVersion"):
            for proto_name, _, tls_version in _SSL_PROTOCOLS:
                if tls_version is not None:
                    versions_to_test.append((proto_name, tls_version))

        for proto_name, tls_version in versions_to_test:
            accepted = self._probe_tls_version(tls_version)
            if accepted:
                result.accepted_protocols.append(proto_name)
                logger.debug("%s:%d accepts %s", self.host, self.port, proto_name)
            else:
                result.rejected_protocols.append(proto_name)

        # Get accepted cipher list for TLS 1.2
        result.accepted_ciphers = self._enumerate_ciphers()

    def _probe_tls_version(self, tls_version: ssl.TLSVersion) -> bool:
        """Test if a specific TLS version is accepted.

        Args:
            tls_version: TLSVersion enum value.

        Returns:
            True if accepted, False otherwise.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except ssl.SSLError:
            return False
        except (socket.error, OSError):
            return False
        except Exception:  # noqa: BLE001
            return False

    def _enumerate_ciphers(self) -> List[str]:
        """Get the list of ciphers accepted for TLS 1.2.

        Returns:
            List of accepted cipher suite names.
        """
        accepted: List[str] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@STRENGTH")
            available = ctx.get_ciphers()
            for cipher_info in available:
                name = cipher_info.get("name", "")
                if name:
                    try:
                        test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        test_ctx.check_hostname = False
                        test_ctx.verify_mode = ssl.CERT_NONE
                        test_ctx.set_ciphers(name)
                        with socket.create_connection((self.host, self.port), timeout=5) as sock:
                            with test_ctx.wrap_socket(sock, server_hostname=self.host):
                                accepted.append(name)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cipher enumeration failed: %s", exc)
        return accepted[:50]  # Limit to prevent excessive connections

    def _generate_findings(self, result: CipherCheckResult) -> List[Finding]:
        """Generate security findings from cipher check results.

        Args:
            result: Populated CipherCheckResult.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []

        # Protocol version findings
        for proto in result.accepted_protocols:
            severity_info = _PROTOCOL_SEVERITY.get(proto)
            if severity_info is None:
                continue  # TLS 1.2 and 1.3 are fine
            severity, cvss = severity_info

            if proto == "SSLv2":
                title = "SSL 2.0 Accepted"
                desc = "SSL 2.0 is a critically insecure protocol with known vulnerabilities. All modern browsers reject it."
                refs = ["https://nvd.nist.gov/vuln/detail/CVE-2011-4762"]
            elif proto == "SSLv3":
                title = "SSL 3.0 Accepted (POODLE)"
                desc = "SSL 3.0 is vulnerable to the POODLE attack (CVE-2014-3566) which allows decryption of HTTPS traffic."
                refs = ["https://nvd.nist.gov/vuln/detail/CVE-2014-3566"]
                findings[-1].cve_ids.append("CVE-2014-3566") if findings else None
            elif proto == "TLSv1.0":
                title = "TLS 1.0 Accepted"
                desc = "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST attack under certain configurations."
                refs = ["https://tools.ietf.org/html/rfc8996"]
            else:  # TLSv1.1
                title = "TLS 1.1 Accepted"
                desc = "TLS 1.1 is deprecated (RFC 8996). While not immediately exploitable, it should be disabled."
                refs = ["https://tools.ietf.org/html/rfc8996"]

            findings.append(Finding(
                title=title,
                severity=severity,  # type: ignore[arg-type]
                category="TLS",
                target=self.host,
                port=self.port,
                description=desc,
                evidence=f"Protocol {proto} was accepted during handshake.",
                remediation=f"Disable {proto} in server configuration. Only TLS 1.2 and TLS 1.3 should be accepted.",
                cvss_score=cvss,
                references=refs,
            ))

        # Cipher suite findings
        seen_cipher_issues: set = set()
        for cipher_name in result.accepted_ciphers:
            for keyword, (title, severity, cvss, desc_extra) in _CIPHER_ISSUES.items():
                if keyword in cipher_name.upper() and title not in seen_cipher_issues:
                    seen_cipher_issues.add(title)
                    matching = [c for c in result.accepted_ciphers if keyword in c.upper()]
                    findings.append(Finding(
                        title=title,
                        severity=severity,  # type: ignore[arg-type]
                        category="TLS",
                        target=self.host,
                        port=self.port,
                        description=f"{desc_extra}. Weak ciphers found: {', '.join(matching[:5])}",
                        evidence=f"Accepted ciphers containing '{keyword}':\n" + "\n".join(matching[:10]),
                        remediation=(
                            f"Remove all {keyword} ciphers from the server TLS configuration. "
                            "Use only ECDHE+AESGCM or CHACHA20 cipher suites."
                        ),
                        cvss_score=cvss,
                        references=["https://ciphersuite.info/"],
                    ))

        # BEAST: CBC ciphers with TLS 1.0
        if "TLSv1.0" in result.accepted_protocols:
            cbc_ciphers = [c for c in result.accepted_ciphers if "CBC" in c.upper() and "TLSv1.0" in c]
            if cbc_ciphers:
                findings.append(Finding(
                    title="BEAST Attack Conditions (TLS 1.0 + CBC)",
                    severity="Medium",
                    category="TLS",
                    target=self.host,
                    port=self.port,
                    description="Server accepts TLS 1.0 with CBC mode ciphers, creating BEAST attack conditions.",
                    evidence=f"TLS 1.0 accepted with CBC ciphers:\n" + "\n".join(cbc_ciphers[:5]),
                    remediation="Disable TLS 1.0 or prioritize ECDHE+AESGCM ciphers. Disable CBC mode ciphers for TLS 1.0.",
                    cvss_score=5.9,
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"],
                    cve_ids=["CVE-2011-3389"],
                ))

        return findings
