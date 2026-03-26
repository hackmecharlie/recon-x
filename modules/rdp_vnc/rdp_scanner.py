# ============================================================
# RECON-X | modules/rdp_vnc/rdp_scanner.py
# Description: RDP service detection via raw socket, NLA check,
#              and BlueKeep (CVE-2019-0708) condition detection
# ============================================================

import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from engine.findings import Finding

logger = logging.getLogger(__name__)

_RDP_PORT = 3389
_CONNECT_TIMEOUT = 10

# X.224 Connection Request PDU (minimal RDP negotiation request)
# Requests PROTOCOL_SSL (0x01) and PROTOCOL_HYBRID (0x02) - NLA
_X224_CONN_REQUEST = bytes([
    # TPKT header (4 bytes): version=3, reserved=0, length=19
    0x03, 0x00, 0x00, 0x13,
    # X.224 CR-TPDU (14 bytes)
    0x0E,  # LI (length indicator)
    0xE0,  # CR (connection request) + CDT
    0x00, 0x00,  # DST-REF
    0x00, 0x00,  # SRC-REF
    0x00,  # Class 0
    # RDP negotiation request (8 bytes)
    0x01,  # TYPE_RDP_NEG_REQ
    0x00,  # flags
    0x08, 0x00,  # length = 8
    0x03, 0x00, 0x00, 0x00,  # requestedProtocols: SSL | HYBRID (NLA)
])

# Minimal request without NLA (to test if no-NLA connection succeeds)
_X224_CONN_REQUEST_NO_NLA = bytes([
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x00, 0x00,  # requestedProtocols: SSL only (no NLA)
])


@dataclass
class RDPScanResult:
    """Results from RDP service scanning."""
    host: str
    port: int = _RDP_PORT
    rdp_open: bool = False
    nla_required: bool = True
    credSSP_supported: bool = False
    protocol_version: str = ""
    raw_response: bytes = b""
    findings: List[Finding] = field(default_factory=list)


class RDPScanner:
    """Detect RDP service characteristics and security posture.

    Sends X.224 Connection Request PDUs to probe NLA enforcement
    and detect BlueKeep-vulnerable conditions.
    """

    def __init__(self, host: str, port: int = _RDP_PORT, timeout: int = _CONNECT_TIMEOUT) -> None:
        """Initialize RDPScanner.

        Args:
            host: Target IP or hostname.
            port: RDP port (default 3389).
            timeout: Socket timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def scan(self) -> RDPScanResult:
        """Perform RDP scan and return structured results.

        Returns:
            RDPScanResult with all findings.
        """
        result = RDPScanResult(host=self.host, port=self.port)

        # First check if RDP port is open
        if not self._is_port_open():
            return result

        result.rdp_open = True
        logger.info("RDP port open on %s:%d", self.host, self.port)

        # Probe with NLA request
        nla_response = self._send_probe(_X224_CONN_REQUEST)
        result.raw_response = nla_response or b""

        # Probe without NLA to check if server allows non-NLA connections
        no_nla_response = self._send_probe(_X224_CONN_REQUEST_NO_NLA)

        # Parse responses to determine NLA enforcement
        result.nla_required = self._parse_nla_required(nla_response, no_nla_response)
        result.credSSP_supported = self._parse_credSSP(nla_response)

        # Generate findings
        result.findings = self._generate_findings(result)
        return result

    def _is_port_open(self) -> bool:
        """Quick TCP port check.

        Returns:
            True if port accepts connections.
        """
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                return True
        except (socket.error, OSError):
            return False

    def _send_probe(self, probe: bytes) -> Optional[bytes]:
        """Send an RDP probe and read the response.

        Args:
            probe: Bytes to send.

        Returns:
            Response bytes, or None on failure.
        """
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(probe)
                response = b""
                sock.settimeout(5)
                try:
                    while True:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                        if len(response) >= 19:
                            break
                except socket.timeout:
                    pass
                return response
        except (socket.error, OSError) as exc:
            logger.debug("RDP probe failed for %s:%d: %s", self.host, self.port, exc)
            return None

    @staticmethod
    def _parse_nla_required(
        nla_response: Optional[bytes],
        no_nla_response: Optional[bytes],
    ) -> bool:
        """Parse RDP negotiation responses to determine NLA enforcement.

        If the server accepts a non-NLA connection, NLA is not required.

        Args:
            nla_response: Response to NLA-capable connection request.
            no_nla_response: Response to non-NLA connection request.

        Returns:
            True if NLA is required, False if not enforced.
        """
        # Check if non-NLA connection was accepted
        if no_nla_response and len(no_nla_response) >= 11:
            # TYPE_RDP_NEG_RSP = 0x02, CC-TPDU = 0xD0
            tpdu_type = no_nla_response[5] if len(no_nla_response) > 5 else 0
            if tpdu_type == 0xD0:  # CC (Connection Confirm)
                # Check if there's an RDP_NEG_RSP
                if len(no_nla_response) >= 19:
                    neg_type = no_nla_response[11]
                    if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                        # selectedProtocol field
                        if len(no_nla_response) >= 19:
                            selected = struct.unpack_from("<I", no_nla_response, 15)[0]
                            # Protocol 1 = SSL only (no NLA) was accepted
                            if selected == 0x00000001:
                                return False  # NLA not required
                    elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                        return True  # Server rejected non-NLA, NLA required
        return True  # Default to assuming NLA required

    @staticmethod
    def _parse_credSSP(response: Optional[bytes]) -> bool:
        """Check if CredSSP was offered in the RDP negotiation.

        Args:
            response: RDP negotiation response bytes.

        Returns:
            True if CredSSP was offered.
        """
        if not response or len(response) < 19:
            return False
        try:
            if response[11] == 0x02:  # TYPE_RDP_NEG_RSP
                selected = struct.unpack_from("<I", response, 15)[0]
                return bool(selected & 0x00000002)  # PROTOCOL_HYBRID bit
        except (IndexError, struct.error):
            pass
        return False

    def _generate_findings(self, result: RDPScanResult) -> List[Finding]:
        """Generate security findings from RDP scan.

        Args:
            result: Populated RDPScanResult.

        Returns:
            List of Finding objects.
        """
        findings: List[Finding] = []

        if not result.rdp_open:
            return findings

        # RDP Exposed to Network
        findings.append(Finding(
            title="RDP Exposed to Network",
            severity="Medium",
            category="RDP",
            target=self.host,
            port=self.port,
            description=(
                f"Remote Desktop Protocol (RDP) is accessible on {self.host}:{self.port}. "
                "Internet-exposed RDP is a common attack vector for brute force, credential stuffing, "
                "and exploitation of RDP vulnerabilities."
            ),
            evidence=f"TCP connection succeeded to {self.host}:{self.port} (RDP service responded)",
            remediation=(
                "1. Restrict RDP access using firewall rules — allow only from trusted IPs\n"
                "2. Place RDP behind a VPN\n"
                "3. Enable Network Level Authentication (NLA)\n"
                "4. Use RD Gateway for external access"
            ),
            cvss_score=5.3,
            references=["https://attack.mitre.org/techniques/T1021/001/"],
        ))

        # NLA not enforced
        if not result.nla_required:
            findings.append(Finding(
                title="RDP Network Level Authentication (NLA) Not Enforced",
                severity="High",
                category="RDP",
                target=self.host,
                port=self.port,
                description=(
                    "RDP does not require Network Level Authentication (NLA). "
                    "Without NLA, unauthenticated users can reach the Windows login screen, "
                    "enabling brute force and potential pre-auth vulnerability exploitation (e.g., BlueKeep)."
                ),
                evidence=(
                    f"RDP connection without NLA was accepted by {self.host}:{self.port}.\n"
                    "Server responded to non-NLA X.224 connection request."
                ),
                remediation=(
                    "Enable NLA via Group Policy:\n"
                    "Computer Configuration → Administrative Templates → Windows Components → "
                    "Remote Desktop Services → Remote Desktop Session Host → Security → "
                    "'Require NLA for connections' = Enabled"
                ),
                cvss_score=7.5,
                references=[
                    "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
                ],
            ))

            # BlueKeep condition detection
            findings.append(Finding(
                title="BlueKeep Conditions Detected (CVE-2019-0708)",
                severity="Critical",
                category="RDP",
                target=self.host,
                port=self.port,
                description=(
                    "The conditions for BlueKeep (CVE-2019-0708) are present: RDP is open "
                    "and NLA is not enforced. BlueKeep is a pre-authentication RCE vulnerability "
                    "affecting Windows 7, Server 2008 R2, and earlier Windows versions. "
                    "NOTE: This is a condition detection, NOT active exploitation."
                ),
                evidence=(
                    f"RDP open: {self.host}:{self.port}\n"
                    "NLA enforcement: Disabled\n"
                    "Detection method: X.224 negotiation response analysis\n"
                    "IMPORTANT: Full exploitation requires Windows pre-7/2008R2 - verify OS version."
                ),
                remediation=(
                    "1. Apply MS19-0708 security update immediately\n"
                    "2. Enable NLA on all RDP endpoints\n"
                    "3. Block TCP 3389 at the perimeter firewall\n"
                    "4. Isolate affected hosts pending patching"
                ),
                cve_ids=["CVE-2019-0708"],
                cvss_score=9.8,
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
                    "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708",
                ],
            ))

        return findings
