# ============================================================
# RECON-X | modules/web/banner_grabber.py
# Description: Raw TCP banner grabbing across open ports with
#              protocol-appropriate probes and version extraction
# ============================================================

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional

from engine.findings import BannerResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 5
_BUFFER_SIZE = 4096

# Port-specific probes
_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    21: b"",  # FTP sends banner on connect
    22: b"",  # SSH sends banner on connect
    23: b"",  # Telnet sends banner on connect
    25: b"",  # SMTP sends banner on connect
    110: b"",  # POP3
    143: b"",  # IMAP
    3306: b"",  # MySQL
    5432: b"",  # PostgreSQL
    6379: b"PING\r\n",
    27017: b"",  # MongoDB
}

# Patterns to extract version strings from banners
_VERSION_PATTERNS: list[re.Pattern] = [
    re.compile(r"SSH-[\d.]+-(\S+)", re.IGNORECASE),
    re.compile(r"Server:\s*(\S.*)", re.IGNORECASE),
    re.compile(r"OpenSSH[_\s]([\d.]+)", re.IGNORECASE),
    re.compile(r"vsftpd\s*([\d.]+)", re.IGNORECASE),
    re.compile(r"ProFTPD\s*([\d.]+)", re.IGNORECASE),
    re.compile(r"Postfix\s*([\d.]+)", re.IGNORECASE),
    re.compile(r"nginx/([\d.]+)", re.IGNORECASE),
    re.compile(r"Apache/([\d.]+)", re.IGNORECASE),
    re.compile(r"IIS/([\d.]+)", re.IGNORECASE),
    re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE),
    re.compile(r"([\d]+\.[\d]+\.[\d]+)", re.IGNORECASE),  # Generic version x.y.z
]

# Hints about protocol from banner content
_PROTOCOL_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-", re.IGNORECASE), "SSH"),
    (re.compile(r"^220.*FTP", re.IGNORECASE), "FTP"),
    (re.compile(r"^220.*SMTP|^220.*ESMTP", re.IGNORECASE), "SMTP"),
    (re.compile(r"HTTP/\d", re.IGNORECASE), "HTTP"),
    (re.compile(r"^\+OK|^-ERR", re.IGNORECASE), "POP3"),
    (re.compile(r"^\* OK.*IMAP", re.IGNORECASE), "IMAP"),
    (re.compile(r"\+PONG", re.IGNORECASE), "Redis"),
    (re.compile(r"mysql_native_password|MariaDB", re.IGNORECASE), "MySQL"),
]


def _get_probe(port: int, host: str) -> bytes:
    """Return the appropriate probe bytes for a given port.

    Args:
        port: Target port number.
        host: Target hostname (used in HTTP Host header).

    Returns:
        Bytes to send as a probe.
    """
    probe = _PROBES.get(port)
    if probe is None:
        return b"\r\n"  # Generic probe
    if b"{host}" in probe:
        return probe.replace(b"{host}", host.encode("ascii", errors="replace"))
    return probe


def _detect_protocol(banner: str) -> str:
    """Detect protocol hint from banner text.

    Args:
        banner: Raw banner string.

    Returns:
        Protocol name string, or empty string if unknown.
    """
    for pattern, name in _PROTOCOL_HINTS:
        if pattern.search(banner):
            return name
    return ""


def _extract_version(banner: str) -> str:
    """Extract a version string from a banner using regex patterns.

    Args:
        banner: Raw banner string.

    Returns:
        Version string if found, empty string otherwise.
    """
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            return m.group(1)
    return ""


class BannerGrabber:
    """Grab banners from open TCP ports using raw socket connections.

    Sends protocol-appropriate probes and extracts version strings
    and protocol hints from the responses.
    """

    def __init__(
        self,
        host: str,
        ports: List[int],
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize BannerGrabber.

        Args:
            host: Target IP or hostname.
            ports: List of port numbers to probe.
            timeout: Per-connection timeout in seconds.
        """
        self.host = host
        self.ports = ports
        self.timeout = timeout

    async def grab_all(self) -> List[BannerResult]:
        """Grab banners from all specified ports concurrently.

        Returns:
            List of BannerResult objects (one per port).
        """
        tasks = [self._grab_one(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        banners: List[BannerResult] = []
        for r in results:
            if isinstance(r, BannerResult):
                banners.append(r)
            elif isinstance(r, Exception):
                logger.debug("Banner grab exception: %s", r)
        return banners

    async def _grab_one(self, port: int) -> BannerResult:
        """Grab a banner from a single port.

        Args:
            port: Port number to probe.

        Returns:
            BannerResult for this port.
        """
        result = BannerResult(host=self.host, port=port)
        probe = _get_probe(port, self.host)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            result.error = str(exc)
            return result

        try:
            # Send probe if needed
            if probe:
                writer.write(probe)
                await writer.drain()

            # Read response with timeout
            try:
                banner_bytes = await asyncio.wait_for(
                    reader.read(_BUFFER_SIZE),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                banner_bytes = b""

            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            result.banner = banner[:1000]  # Truncate long banners
            result.protocol_hint = _detect_protocol(banner)
            result.service_version = _extract_version(banner)
            logger.debug("Banner from %s:%d: %r", self.host, port, banner[:80])
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        return result
