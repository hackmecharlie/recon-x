# ============================================================
# RECON-X | modules/tls/cert_analyzer.py
# Description: Retrieve and analyze TLS certificate chains
#              using sslyze and cryptography libraries
# ============================================================

import logging
import ssl
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from engine.findings import CertificateResult, Finding

logger = logging.getLogger(__name__)


class CertAnalyzer:
    """Retrieve and analyze TLS certificate chains.

    Uses sslyze for structured scanning and falls back to the
    built-in ssl module for basic connectivity.
    """

    def __init__(self, host: str, port: int = 443, timeout: int = 10) -> None:
        """Initialize CertAnalyzer.

        Args:
            host: Target hostname or IP.
            port: TLS port (default 443).
            timeout: Connection timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    async def analyze(self) -> CertificateResult:
        """Retrieve and analyze the TLS certificate.

        Returns:
            CertificateResult with all certificate metadata and findings.
        """
        result = CertificateResult(host=self.host, port=self.port)
        findings: List[Finding] = []

        try:
            cert_info = self._get_cert_via_ssl()
            if cert_info:
                self._populate_result(result, cert_info, findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Certificate analysis failed for %s:%d: %s", self.host, self.port, exc)

        result.findings = findings
        return result

    def _get_cert_via_ssl(self) -> Optional[dict]:
        """Retrieve certificate using Python's ssl module.

        Returns:
            Certificate dict or None on failure.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert) if der_cert else None
                    cert_dict = ssock.getpeercert() or {}
                    return {"dict": cert_dict, "pem": pem_cert, "der": der_cert}
        except (ssl.SSLError, socket.error, OSError) as exc:
            logger.debug("SSL connection failed for %s:%d: %s", self.host, self.port, exc)
            return None

    def _populate_result(
        self, result: CertificateResult, cert_info: dict, findings: List[Finding]
    ) -> None:
        """Populate CertificateResult and generate findings from cert data.

        Args:
            result: CertificateResult to populate in-place.
            cert_info: Raw cert data from ssl module.
            findings: List to append findings to.
        """
        cert_dict = cert_info.get("dict", {})
        pem = cert_info.get("pem", "")
        result.raw_pem = pem or ""

        # Try cryptography library for richer parsing
        if cert_info.get("der"):
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import rsa, ec

                cert = x509.load_der_x509_certificate(cert_info["der"])
                subject = cert.subject

                # Extract subject fields
                try:
                    result.subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                except (IndexError, Exception):
                    result.subject_cn = ""
                try:
                    result.subject_o = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
                except (IndexError, Exception):
                    result.subject_o = ""
                try:
                    result.subject_c = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
                except (IndexError, Exception):
                    result.subject_c = ""

                # Issuer
                issuer = cert.issuer
                try:
                    result.issuer_cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                except (IndexError, Exception):
                    result.issuer_cn = ""

                # Self-signed detection
                result.is_self_signed = cert.issuer == cert.subject

                # Serial number
                result.serial = str(cert.serial_number)

                # Key info
                pub_key = cert.public_key()
                if isinstance(pub_key, rsa.RSAPublicKey):
                    result.key_algorithm = "RSA"
                    result.key_size = pub_key.key_size
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    result.key_algorithm = "ECDSA"
                    result.key_size = pub_key.key_size

                # Signature algorithm
                try:
                    result.signature_algorithm = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else ""
                except Exception:  # noqa: BLE001
                    result.signature_algorithm = ""

                # Validity dates
                not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                result.valid_from = not_before.isoformat()
                result.valid_until = not_after.isoformat()
                result.is_expired = now > not_after
                result.days_until_expiry = (not_after - now).days

                # SANs
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    result.sans = [str(name.value) for name in san_ext.value]
                except x509.ExtensionNotFound:
                    result.sans = []
                except Exception:  # noqa: BLE001
                    result.sans = []

                # Generate findings
                findings.extend(self._generate_findings(result))

            except ImportError:
                logger.debug("cryptography library not available, using basic cert info")
                self._populate_basic(result, cert_dict, findings)
        else:
            self._populate_basic(result, cert_dict, findings)

    def _populate_basic(
        self, result: CertificateResult, cert_dict: dict, findings: List[Finding]
    ) -> None:
        """Populate from ssl.getpeercert() dict when cryptography unavailable."""
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))
        result.subject_cn = subject.get("commonName", "")
        result.issuer_cn = issuer.get("commonName", "")
        result.is_self_signed = subject == issuer

        not_after_str = cert_dict.get("notAfter", "")
        if not_after_str:
            try:
                from dateutil import parser as du_parser
                not_after = du_parser.parse(not_after_str)
                now = datetime.now(timezone.utc)
                result.valid_until = not_after.isoformat()
                result.is_expired = now > not_after
                result.days_until_expiry = (not_after - now).days
            except Exception:  # noqa: BLE001
                pass

        # SANs
        for san_entry in cert_dict.get("subjectAltName", []):
            if san_entry[0] == "DNS":
                result.sans.append(san_entry[1])

        findings.extend(self._generate_findings(result))

    def _generate_findings(self, result: CertificateResult) -> List[Finding]:
        """Generate security findings from analyzed certificate."""
        findings: List[Finding] = []
        target_str = f"{self.host}:{self.port}"

        # Expired certificate
        if result.is_expired:
            findings.append(Finding(
                title="TLS Certificate Expired",
                severity="Critical",
                category="TLS",
                target=self.host,
                port=self.port,
                description=(
                    f"The TLS certificate for {self.host} has expired. "
                    f"Expired: {result.valid_until}. "
                    "Expired certificates cause browser security warnings and indicate poor certificate lifecycle management."
                ),
                evidence=f"Certificate CN: {result.subject_cn}\nExpiry: {result.valid_until}\nDays expired: {abs(result.days_until_expiry or 0)}",
                remediation="Renew the TLS certificate immediately. Consider using Let's Encrypt with automated renewal.",
                cvss_score=9.0,
                references=["https://tools.ietf.org/html/rfc5280"],
            ))

        # Expiring soon
        elif result.days_until_expiry is not None:
            if result.days_until_expiry < 30:
                findings.append(Finding(
                    title="TLS Certificate Expiring Soon (<30 days)",
                    severity="Critical",
                    category="TLS",
                    target=self.host,
                    port=self.port,
                    description=f"Certificate expires in {result.days_until_expiry} days ({result.valid_until}).",
                    evidence=f"CN: {result.subject_cn}\nExpiry: {result.valid_until}\nDays remaining: {result.days_until_expiry}",
                    remediation="Renew the certificate before expiration to avoid service disruption.",
                    cvss_score=7.0,
                ))
            elif result.days_until_expiry < 90:
                findings.append(Finding(
                    title="TLS Certificate Expiring Soon (<90 days)",
                    severity="High",
                    category="TLS",
                    target=self.host,
                    port=self.port,
                    description=f"Certificate expires in {result.days_until_expiry} days ({result.valid_until}).",
                    evidence=f"CN: {result.subject_cn}\nExpiry: {result.valid_until}\nDays remaining: {result.days_until_expiry}",
                    remediation="Plan certificate renewal within the next 30 days.",
                    cvss_score=3.7,
                ))

        # Self-signed
        if result.is_self_signed:
            findings.append(Finding(
                title="Self-Signed TLS Certificate",
                severity="Medium",
                category="TLS",
                target=self.host,
                port=self.port,
                description="The server is using a self-signed certificate not issued by a trusted CA.",
                evidence=f"Subject: {result.subject_cn}\nIssuer: {result.issuer_cn}\nSelf-signed: yes",
                remediation="Replace the self-signed certificate with one issued by a trusted Certificate Authority.",
                cvss_score=5.4,
            ))

        # Weak signature algorithm
        sig_alg = (result.signature_algorithm or "").upper()
        if "MD5" in sig_alg:
            findings.append(Finding(
                title="Weak Certificate Signature Algorithm (MD5)",
                severity="Critical",
                category="TLS",
                target=self.host,
                port=self.port,
                description="Certificate uses MD5 signature algorithm, which is cryptographically broken and can be forged.",
                evidence=f"Signature algorithm: {result.signature_algorithm}",
                remediation="Replace certificate with one using SHA-256 or stronger.",
                cvss_score=9.0,
                references=["https://nvd.nist.gov/vuln/detail/CVE-2004-2761"],
            ))
        elif "SHA1" in sig_alg:
            findings.append(Finding(
                title="Weak Certificate Signature Algorithm (SHA1)",
                severity="High",
                category="TLS",
                target=self.host,
                port=self.port,
                description="Certificate uses SHA-1 signature algorithm. SHA-1 is deprecated and no longer considered secure.",
                evidence=f"Signature algorithm: {result.signature_algorithm}",
                remediation="Replace certificate with one using SHA-256 or stronger.",
                cvss_score=7.4,
            ))

        # Weak RSA key
        if result.key_algorithm == "RSA" and result.key_size and result.key_size < 2048:
            findings.append(Finding(
                title="Weak RSA Key Size",
                severity="High",
                category="TLS",
                target=self.host,
                port=self.port,
                description=f"Certificate uses {result.key_size}-bit RSA key. Keys below 2048 bits are considered weak.",
                evidence=f"Key algorithm: RSA\nKey size: {result.key_size} bits",
                remediation="Regenerate the key pair with at least 2048 bits (4096 recommended).",
                cvss_score=7.5,
            ))

        # Hostname mismatch
        if result.subject_cn and self.host:
            cn = result.subject_cn
            host_lower = self.host.lower()
            cn_lower = cn.lower()
            san_lower = [s.lower() for s in result.sans]
            wildcard_match = any(
                s.startswith("*.") and host_lower.endswith(s[1:])
                for s in san_lower
            )
            exact_match = host_lower in san_lower or cn_lower == host_lower
            if not exact_match and not wildcard_match and result.sans:
                findings.append(Finding(
                    title="TLS Certificate Hostname Mismatch",
                    severity="Critical",
                    category="TLS",
                    target=self.host,
                    port=self.port,
                    description=(
                        f"The certificate CN '{cn}' does not match the target hostname '{self.host}'. "
                        f"SANs: {', '.join(result.sans[:5])}"
                    ),
                    evidence=f"Host: {self.host}\nCN: {cn}\nSANs: {', '.join(result.sans)}",
                    remediation="Issue a new certificate that includes the correct hostname as a Subject Alternative Name.",
                    cvss_score=9.0,
                ))

        # Wildcard cert (informational)
        if result.subject_cn and result.subject_cn.startswith("*"):
            findings.append(Finding(
                title="Wildcard TLS Certificate",
                severity="Informational",
                category="TLS",
                target=self.host,
                port=self.port,
                description=f"Certificate uses a wildcard: {result.subject_cn}. Wildcard certs cover all subdomains, which may pose risk if one subdomain is compromised.",
                evidence=f"CN: {result.subject_cn}",
                remediation="Consider using per-service certificates for sensitive subdomains.",
            ))

        return findings
