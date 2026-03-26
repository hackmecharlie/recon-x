# ============================================================
# RECON-X | modules/nmap/nmap_parser.py
# Description: Parse nmap XML output into structured Port objects
#              and extract NSE script results
# ============================================================

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from engine.findings import Port

logger = logging.getLogger(__name__)

# Service name to likely scan modules mapping
_SERVICE_MODULE_HINTS: Dict[str, List[str]] = {
    "http": ["web", "headers", "clickjack", "screenshot"],
    "https": ["web", "tls", "headers", "clickjack", "screenshot"],
    "ssl/http": ["web", "tls", "headers", "clickjack", "screenshot"],
    "microsoft-ds": ["smb"],
    "netbios-ssn": ["smb"],
    "ms-wbt-server": ["rdp"],
    "vnc": ["vnc"],
    "telnet": ["telnet"],
    "ftp": ["ftp", "banner"],
    "smtp": ["smtp", "banner"],
    "ssh": ["ssh", "banner"],
}


class NmapParser:
    """Parse raw nmap XML into Port objects.

    Extracts: port number, protocol, state, service, version,
    product, extra info, banner text, and NSE script output.
    """

    def parse(self, xml_content: str) -> List[Port]:
        """Parse nmap XML and return list of open Port objects.

        Args:
            xml_content: Raw nmap XML string.

        Returns:
            List of Port objects for open ports only.
        """
        if not xml_content.strip():
            return []

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            logger.warning("Failed to parse nmap XML: %s", exc)
            return []

        ports: List[Port] = []
        for host_elem in root.findall(".//host"):
            # Skip hosts that are down
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            for port_elem in host_elem.findall(".//port"):
                port = self._parse_port(port_elem)
                if port and port.state == "open":
                    ports.append(port)

        logger.debug("nmap_parser: found %d open ports", len(ports))
        return ports

    def _parse_port(self, port_elem: ET.Element) -> Optional[Port]:
        """Parse a single <port> XML element into a Port object.

        Args:
            port_elem: The <port> XML element.

        Returns:
            Port object, or None if state is not 'open'.
        """
        port_num = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        if state_elem is None:
            return None
        state = state_elem.get("state", "unknown")

        service_elem = port_elem.find("service")
        service_name = ""
        service_version = ""
        product = ""
        extrainfo = ""
        banner = ""

        if service_elem is not None:
            service_name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            service_version = service_elem.get("version", "")
            extrainfo = service_elem.get("extrainfo", "")

        # Extract NSE script outputs
        scripts_output: Dict[str, str] = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id", "")
            script_output = script_elem.get("output", "")
            if script_id:
                scripts_output[script_id] = script_output
            # Extract banner from banner script
            if script_id == "banner":
                banner = script_output

        # Also check for http-banner or other banner-style scripts
        if not banner:
            for key in ("http-server-header", "ssl-cert", "banner"):
                if key in scripts_output:
                    banner = scripts_output[key][:500]
                    break

        return Port(
            port_number=port_num,
            protocol=protocol,
            state=state,
            service_name=service_name,
            service_version=service_version,
            product=product,
            extrainfo=extrainfo,
            banner=banner,
            scripts_output=scripts_output,
        )

    def extract_os_info(self, xml_content: str) -> Optional[str]:
        """Extract OS detection result from nmap XML.

        Args:
            xml_content: Raw nmap XML string.

        Returns:
            OS name string if found, else None.
        """
        if not xml_content.strip():
            return None
        try:
            root = ET.fromstring(xml_content)
            for osmatch in root.findall(".//osmatch"):
                name = osmatch.get("name")
                if name:
                    return name
        except ET.ParseError:
            pass
        return None

    def get_module_hints(self, ports: List[Port]) -> Dict[str, bool]:
        """Determine which scan modules should run based on open ports.

        Args:
            ports: List of detected open ports.

        Returns:
            Dict mapping module names to True if they should run.
        """
        modules: Dict[str, bool] = {}
        for port in ports:
            svc = (port.service_name or "").lower()
            hints = _SERVICE_MODULE_HINTS.get(svc, [])
            for module in hints:
                modules[module] = True
            # Port-number-based hints
            if port.port_number in (80, 8080, 8000):
                modules["web"] = True
            if port.port_number in (443, 8443):
                modules["tls"] = True
                modules["web"] = True
            if port.port_number in (445, 139):
                modules["smb"] = True
            if port.port_number == 3389:
                modules["rdp"] = True
            if port.port_number == 23:
                modules["telnet"] = True
            if 5900 <= port.port_number <= 5910:
                modules["vnc"] = True
        return modules

    def extract_vuln_script_results(self, ports: List[Port]) -> Dict[str, str]:
        """Collect all vuln NSE script outputs from parsed ports.

        Args:
            ports: List of Port objects with scripts_output populated.

        Returns:
            Dict mapping script_id to output string.
        """
        results: Dict[str, str] = {}
        for port in ports:
            for script_id, output in port.scripts_output.items():
                if "vuln" in script_id.lower() or script_id.startswith("smb-vuln"):
                    results[f"{port.port_number}/{script_id}"] = output
        return results
