# ============================================================
# RECON-X | modules/rdp_vnc/vnc_telnet.py
# Description: VNC protocol detection (auth type, version) and
#              Telnet banner grabbing with device fingerprinting
# ============================================================

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional

from engine.findings import Finding

logger = logging.getLogger(__name__)

_VNC_TIMEOUT = 10
_TELNET_TIMEOUT = 5
_BUFFER_SIZE = 2048

# VNC security type codes
_VNC_SECURITY_NONE = 1
_VNC_SECURITY_VNC_AUTH = 2
_VNC_SECURITY_RA2 = 5
_VNC_SECURITY_RA2NE = 6
_VNC_SECURITY_TIGHT = 16
_VNC_SECURITY_ULTRA = 17
_VNC_SECURITY_TLS = 18
_VNC_SECURITY_VENCRYPT = 19
_VNC_SECURITY_GTK_VNC_SASL = 20
_VNC_SECURITY_MD5_HASH = 21
_VNC_SECURITY_COLIN_DEAN_XVP = 22
_VNC_SECURITY_SECURE_TUNNEL = 23
_VNC_SECURITY_INTEGRATED_SSH = 24

# Device type keywords for Telnet fingerprinting
_DEVICE_KEYWORDS = [
    ("Cisco", ["cisco", "ios", "catalyst"]),
    ("Juniper", ["juniper", "junos"]),
    ("Linux", ["linux", "ubuntu", "debian", "centos", "fedora", "redhat"]),
    ("Windows", ["windows", "microsoft"]),
    ("MikroTik", ["mikrotik", "routeros"]),
    ("Huawei", ["huawei", "vrp"]),
    ("HP", ["hp", "hewlett", "procurve", "aruba"]),
    ("Dell", ["dell", "emc", "powerconnect"]),
    ("F5", ["f5", "big-ip", "tmsh"]),
    ("Fortinet", ["fortinet", "fortigate", "fortiswitch"]),
]


@dataclass
class VNCScanResult:
    """Results from VNC service scanning."""
    host: str
    port: int
    open: bool = False
    rfb_version: str = ""
    security_types: List[int] = field(default_factory=list)
    no_auth: bool = False
    weak_auth: bool = False
    findings: List[Finding] = field(default_factory=list)


@dataclass
class TelnetScanResult:
    """Results from Telnet banner grabbing."""
    host: str
    port: int = 23
    open: bool = False
    banner: str = ""
    device_type: str = ""
    findings: List[Finding] = field(default_factory=list)


class VNCScanner:
    """Detect VNC service security type and protocol version.

    Connects to RFB (VNC) ports and parses the initial handshake
    to determine authentication requirements.
    """

    def __init__(self, host: str, port: int = 5900, timeout: int = _VNC_TIMEOUT) -> None:
        """Initialize VNCScanner.

        Args:
            host: Target IP or hostname.
            port: VNC port (default 5900).
            timeout: Socket timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def scan(self) -> VNCScanResult:
        """Scan the VNC service.

        Returns:
            VNCScanResult with version, auth types, and findings.
        """
        result = VNCScanResult(host=self.host, port=self.port)

        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.error, OSError) as exc:
            logger.debug("VNC connect failed %s:%d: %s", self.host, self.port, exc)
            return result

        result.open = True

        try:
            sock.settimeout(self.timeout)

            # Read RFB protocol version string (12 bytes: "RFB xxx.yyy\n")
            version_bytes = self._recv_exact(sock, 12)
            if not version_bytes or not version_bytes.startswith(b"RFB "):
                logger.debug("Not RFB on %s:%d", self.host, self.port)
                return result

            rfb_version = version_bytes.decode("ascii", errors="replace").strip()
            result.rfb_version = rfb_version
            logger.debug("VNC %s:%d version: %s", self.host, self.port, rfb_version)

            # Send client version (use 3.8 for broadest compatibility)
            sock.sendall(b"RFB 003.008\n")

            # Read number of security types (RFB 3.7+)
            num_types_bytes = self._recv_exact(sock, 1)
            if not num_types_bytes:
                return result
            num_types = num_types_bytes[0]

            if num_types == 0:
                # Error condition — server rejected connection
                logger.debug("VNC server sent 0 security types (error)")
                return result

            # Read the security type bytes
            sec_types_bytes = self._recv_exact(sock, num_types)
            if not sec_types_bytes:
                return result

            result.security_types = list(sec_types_bytes)
            result.no_auth = _VNC_SECURITY_NONE in result.security_types
            result.weak_auth = _VNC_SECURITY_VNC_AUTH in result.security_types and not result.no_auth

        except (socket.error, OSError, UnicodeDecodeError) as exc:
            logger.debug("VNC scan error %s:%d: %s", self.host, self.port, exc)
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        result.findings = self._generate_findings(result)
        return result

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from the socket.

        Args:
            sock: Connected socket.
            n: Number of bytes to receive.

        Returns:
            Bytes received, or None on failure.
        """
        buf = b""
        try:
            while len(buf) < n:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    return buf if buf else None
                buf += chunk
        except (socket.error, OSError):
            return buf if buf else None
        return buf

    def _generate_findings(self, result: VNCScanResult) -> List[Finding]:
        """Generate VNC security findings.

        Args:
            result: Populated VNCScanResult.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []

        if not result.open:
            return findings

        if result.no_auth:
            findings.append(Finding(
                title="VNC No Authentication Required",
                severity="Critical",
                category="VNC",
                target=self.host,
                port=self.port,
                description=(
                    f"VNC on port {self.port} accepts connections with security type None (0x01), "
                    "meaning no password is required. Anyone on the network can take full control "
                    "of this system's desktop."
                ),
                evidence=(
                    f"RFB version: {result.rfb_version}\n"
                    f"Security types offered: {result.security_types}\n"
                    "Security type 1 (None/No auth) is present."
                ),
                remediation=(
                    "1. Configure VNC to require password authentication\n"
                    "2. Consider switching to NLA or certificate-based auth (VeNCrypt)\n"
                    "3. Restrict VNC access with firewall rules\n"
                    "4. Tunnel VNC over SSH for encrypted access"
                ),
                cvss_score=9.8,
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ))
        elif result.weak_auth:
            findings.append(Finding(
                title="VNC Weak Authentication (Password Only)",
                severity="Medium",
                category="VNC",
                target=self.host,
                port=self.port,
                description=(
                    f"VNC on port {self.port} uses only VNC password authentication (security type 2). "
                    "VNC passwords are limited to 8 characters, making them susceptible to brute force."
                ),
                evidence=(
                    f"RFB version: {result.rfb_version}\n"
                    f"Security types offered: {result.security_types}\n"
                    "Only security type 2 (VNC auth) is available."
                ),
                remediation=(
                    "1. Upgrade to a stronger authentication method (VeNCrypt with certificate)\n"
                    "2. Use SSH tunneling for VNC connections\n"
                    "3. Enforce a strong, unique password"
                ),
                cvss_score=7.5,
            ))
        else:
            # VNC is open but with stronger auth - informational
            auth_names = {
                _VNC_SECURITY_RA2: "RA2",
                _VNC_SECURITY_TIGHT: "Tight",
                _VNC_SECURITY_TLS: "TLS",
                _VNC_SECURITY_VENCRYPT: "VeNCrypt",
            }
            auth_str = ", ".join(
                auth_names.get(t, str(t)) for t in result.security_types
            )
            findings.append(Finding(
                title="VNC Service Detected",
                severity="Informational",
                category="VNC",
                target=self.host,
                port=self.port,
                description=f"VNC service detected with auth types: {auth_str}.",
                evidence=f"RFB version: {result.rfb_version}\nSecurity types: {result.security_types}",
                remediation="Verify VNC access is intentional and properly secured. Restrict with firewall rules.",
            ))

        return findings


class TelnetScanner:
    """Grab Telnet banners and generate security findings.

    Telnet transmits all data in cleartext, including credentials,
    and should be replaced by SSH on all platforms.
    """

    def __init__(self, host: str, port: int = 23, timeout: int = _TELNET_TIMEOUT) -> None:
        """Initialize TelnetScanner.

        Args:
            host: Target IP or hostname.
            port: Telnet port (default 23).
            timeout: Socket timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def scan(self) -> TelnetScanResult:
        """Connect to Telnet, grab banner, and classify device.

        Returns:
            TelnetScanResult with banner, device type, and findings.
        """
        result = TelnetScanResult(host=self.host, port=self.port)

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                result.open = True

                # Read initial banner (may include IAC negotiation bytes)
                raw = b""
                try:
                    while len(raw) < _BUFFER_SIZE:
                        chunk = sock.recv(256)
                        if not chunk:
                            break
                        raw += chunk
                        # Stop if we have enough data
                        if len(raw) > 512:
                            break
                except socket.timeout:
                    pass

                # Strip Telnet IAC (0xFF) negotiation sequences
                banner = self._strip_iac(raw)
                result.banner = banner[:1000]
                result.device_type = self._detect_device_type(banner)
                logger.info("Telnet open on %s:%d, device: %s", self.host, self.port, result.device_type or "unknown")

        except (socket.error, OSError) as exc:
            logger.debug("Telnet failed %s:%d: %s", self.host, self.port, exc)
            return result

        result.findings = self._generate_findings(result)
        return result

    @staticmethod
    def _strip_iac(data: bytes) -> str:
        """Remove Telnet IAC sequences and return printable text.

        Args:
            data: Raw bytes from Telnet connection.

        Returns:
            Cleaned string with IAC sequences removed.
        """
        result_bytes = bytearray()
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 0xFF:  # IAC
                i += 1
                if i < len(data):
                    cmd = data[i]
                    if cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT
                        i += 2  # Skip option byte
                    elif cmd == 0xFF:
                        result_bytes.append(0xFF)  # Escaped IAC
                        i += 1
                    else:
                        i += 1
            elif 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D):
                result_bytes.append(byte)
                i += 1
            else:
                i += 1
        return result_bytes.decode("ascii", errors="replace")

    @staticmethod
    def _detect_device_type(banner: str) -> str:
        """Detect device/OS type from banner keywords.

        Args:
            banner: Cleaned banner text.

        Returns:
            Device type string, or empty string if unknown.
        """
        banner_lower = banner.lower()
        for device_name, keywords in _DEVICE_KEYWORDS:
            if any(kw in banner_lower for kw in keywords):
                return device_name
        return ""

    def _generate_findings(self, result: TelnetScanResult) -> List[Finding]:
        """Generate Telnet security findings.

        Args:
            result: Populated TelnetScanResult.

        Returns:
            List of Finding objects.
        """
        if not result.open:
            return []

        device_info = f" Detected device type: {result.device_type}." if result.device_type else ""
        return [Finding(
            title="Telnet Enabled - Cleartext Protocol",
            severity="High",
            category="Network Services",
            target=self.host,
            port=self.port,
            description=(
                f"Telnet service is running on {self.host}:{self.port}.{device_info} "
                "Telnet transmits all data including credentials in cleartext. "
                "Any network observer can capture usernames, passwords, and session data."
            ),
            evidence=(
                f"Telnet banner from {self.host}:{self.port}:\n{result.banner or '(no banner)'}\n"
                f"Device type: {result.device_type or 'unknown'}"
            ),
            remediation=(
                "1. Disable Telnet and replace with SSH (protocol 2)\n"
                "2. For network devices: enable SSH and disable Telnet in configuration\n"
                "   - Cisco: 'transport input ssh' on VTY lines\n"
                "   - Juniper: 'set system services ssh'\n"
                "3. Block TCP port 23 at the perimeter firewall"
            ),
            cvss_score=8.1,
            references=[
                "https://attack.mitre.org/techniques/T1021/004/",
                "https://tools.ietf.org/html/rfc4253",
            ],
        )]
