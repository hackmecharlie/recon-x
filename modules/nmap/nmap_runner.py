# ============================================================
# RECON-X | modules/nmap/nmap_runner.py
# Description: Wraps python-nmap to execute scans with three
#              profiles and returns structured XML output
# ============================================================

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_PROFILE_FLAGS: Dict[str, str] = {
    "quick": "-T4 --top-ports 100",
    "normal": "-T3 -sV -sC --top-ports 1000",
    "full": "-T3 -sV -sC -O --top-ports 5000 --script=vuln",
}

_DISCOVERY_FLAGS = "-sn -PE -PS22,80,443,3389 -PA80,443 --max-retries 1 -T4"


class NmapRunner:
    """Wraps nmap execution with structured XML output.

    Supports three scan profiles: quick, normal, full.
    Always uses -oX for reliable XML parsing.
    """

    def __init__(self, profile: str = "normal", nmap_path: str = "nmap") -> None:
        """Initialize NmapRunner.

        Args:
            profile: Scan profile - quick, normal, or full.
            nmap_path: Path to the nmap binary.
        """
        self.profile = profile
        self.nmap_path = nmap_path
        if profile not in _PROFILE_FLAGS:
            logger.warning("Unknown profile %r, defaulting to normal", profile)
            self.profile = "normal"

    def _run_nmap(self, target: str, flags: str) -> Dict[str, Any]:
        """Execute nmap with the given target and flags, capturing XML.

        Args:
            target: IP address or hostname.
            flags: String of nmap flags.

        Returns:
            Dict with 'xml' (str) and 'returncode' (int).
        """
        if not target:
            return {"xml": "", "returncode": -1, "error": "Empty target"}

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = [self.nmap_path] + flags.split() + ["-oX", xml_path, target]
        logger.debug("Running nmap: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # Increased from 600 to 900 seconds
            )
            xml_content = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            Path(xml_path).unlink(missing_ok=True)
            return {
                "xml": xml_content,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired:
            logger.warning("Nmap timed out for target %s", target)
            Path(xml_path).unlink(missing_ok=True)
            return {"xml": "", "returncode": -1, "error": "timeout"}
        except FileNotFoundError:
            logger.error("Nmap binary not found at %r", self.nmap_path)
            return {"xml": "", "returncode": -1, "error": "nmap not found"}
        except OSError as exc:
            logger.error("Nmap execution error for %s: %s", target, exc)
            return {"xml": "", "returncode": -1, "error": str(exc)}

    def quick_discovery(self, target: str) -> Dict[str, Any]:
        """Perform a fast host discovery scan to check if a host is alive.

        Uses ping sweep + TCP ACK/SYN probes on common ports.

        Args:
            target: IP address or hostname to probe.

        Returns:
            Dict with 'alive' bool and raw XML.
        """
        result = self._run_nmap(target, _DISCOVERY_FLAGS)
        alive = False
        xml = result.get("xml", "")
        if xml:
            # Host is alive if nmap found it "up"
            alive = 'status state="up"' in xml or "<host>" in xml
        return {"alive": alive, "xml": xml}

    def run_scan(self, target: str) -> Dict[str, Any]:
        """Run a full scan using the configured profile.

        Args:
            target: IP address or hostname.

        Returns:
            Dict with 'xml' (raw nmap XML), 'returncode', and optionally 'error'.
        """
        flags = _PROFILE_FLAGS[self.profile]
        return self._run_nmap(target, flags)

    def run_smb_scripts(self, target: str) -> Dict[str, Any]:
        """Run comprehensive nmap SMB NSE scripts for vulnerability assessment.

        Args:
            target: Target IP or hostname.

        Returns:
            Dict with XML output.
        """
        flags = (
            "-p 445,139 "
            "--script=smb-security-mode,smb2-security-mode,smb-protocols,"
            "smb-vuln-*,smb2-vuln-* "
            "-T4 --script-timeout=5m"
        )
        return self._run_nmap(target, flags)
