# ============================================================
# RECON-X | core/input_parser.py
# Description: Smart input parser for mixed target formats including
#              IPv4, CIDR, dash ranges, hostnames, URLs, and IPv6
# ============================================================

import re
import socket
import logging
from dataclasses import dataclass, field
from typing import Generator, List, Optional
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Address, AddressValueError
from urllib.parse import urlparse

import netaddr

logger = logging.getLogger(__name__)


@dataclass
class Target:
    """Normalized target object with all resolved metadata."""
    original_input: str
    type: str  # ipv4, ipv6, cidr, hostname, url, subdomain
    ip: Optional[str] = None
    hostname: Optional[str] = None
    schemes: List[str] = field(default_factory=list)
    port_hints: List[int] = field(default_factory=list)
    status: str = "pending"  # pending, unresolvable, alive, dead, timeout

    def __hash__(self) -> int:
        return hash((self.ip or self.hostname, tuple(sorted(self.schemes))))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return False
        return (self.ip or self.hostname) == (other.ip or other.hostname)

    @property
    def display_name(self) -> str:
        """Human-readable name for display and report."""
        if self.hostname:
            return self.hostname
        return self.ip or self.original_input


# Regex patterns for input type detection
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)
_DASH_RANGE_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$"
)
_IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
)
_URL_RE = re.compile(
    r"^https?://", re.IGNORECASE
)
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
)


def _detect_type(entry: str) -> str:
    """Detect the type of a target string."""
    entry = entry.strip()
    if _CIDR_RE.match(entry):
        return "cidr"
    if _DASH_RANGE_RE.match(entry):
        return "dash_range"
    if _IPV4_RE.match(entry):
        try:
            ip_address(entry)
            return "ipv4"
        except ValueError:
            pass
    if _IPV6_RE.match(entry):
        try:
            IPv6Address(entry)
            return "ipv6"
        except (ValueError, AddressValueError):
            pass
    if _URL_RE.match(entry):
        return "url"
    if _HOSTNAME_RE.match(entry):
        return "hostname"
    return "unknown"


def _resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IP address. Returns None if unresolvable."""
    try:
        result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        if result:
            return result[0][4][0]
    except (socket.gaierror, socket.herror, OSError) as exc:
        logger.debug("DNS resolution failed for %s: %s", hostname, exc)
    return None


def _extract_port_hints_from_url(parsed: "urlparse") -> List[int]:
    """Extract explicit port hints from a parsed URL."""
    hints: List[int] = []
    if parsed.port:
        hints.append(parsed.port)
    elif parsed.scheme.lower() == "https":
        hints.append(443)
    elif parsed.scheme.lower() == "http":
        hints.append(80)
    return hints


def _generate_cidr_hosts(cidr: str) -> Generator[str, None, None]:
    """Stream host IPs from a CIDR range without loading all into memory."""
    try:
        network = ip_network(cidr, strict=False)
        for host in network.hosts():
            yield str(host)
    except ValueError as exc:
        logger.warning("Invalid CIDR %s: %s", cidr, exc)


def _generate_dash_range_hosts(dash_range: str) -> Generator[str, None, None]:
    """Stream host IPs from a dash range."""
    parts = re.split(r"\s*-\s*", dash_range)
    if len(parts) != 2:
        logger.warning("Invalid dash range: %s", dash_range)
        return
    try:
        start_ip = int(netaddr.IPAddress(parts[0].strip()))
        end_ip = int(netaddr.IPAddress(parts[1].strip()))
        for ip_int in range(start_ip, end_ip + 1):
            yield str(netaddr.IPAddress(ip_int))
    except (netaddr.AddrFormatError, ValueError) as exc:
        logger.warning("Invalid dash range %s: %s", dash_range, exc)


def _build_ip_target(ip_str: str, original: str, entry_type: str) -> Target:
    """Build a Target from a resolved or direct IP address."""
    return Target(
        original_input=original,
        type=entry_type,
        ip=ip_str,
        hostname=None,
        schemes=[],
        port_hints=[],
        status="pending",
    )


def _build_hostname_target(hostname: str, original: str, entry_type: str) -> Target:
    """Resolve hostname and build a Target, including web scheme targets."""
    ip = _resolve_hostname(hostname)
    status = "pending" if ip else "unresolvable"

    # For hostnames and subdomains, always add both http and https
    schemes = ["http", "https"]
    port_hints = [80, 443]

    return Target(
        original_input=original,
        type=entry_type,
        ip=ip,
        hostname=hostname,
        schemes=schemes,
        port_hints=port_hints,
        status=status,
    )


def _build_url_target(url: str) -> Target:
    """Build a Target from a full URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ip = _resolve_hostname(hostname) if hostname else None
    status = "pending" if (ip or not hostname) else "unresolvable"
    port_hints = _extract_port_hints_from_url(parsed)
    scheme = parsed.scheme.lower()

    return Target(
        original_input=url,
        type="url",
        ip=ip,
        hostname=hostname,
        schemes=[scheme],
        port_hints=port_hints,
        status=status,
    )


def _deduplicate_targets(targets: List[Target]) -> List[Target]:
    """Deduplicate targets: same IP from different input formats = one target.
    Merges schemes and port_hints from duplicates."""
    seen: dict[str, Target] = {}
    result: List[Target] = []

    for target in targets:
        key = target.ip or target.hostname or target.original_input
        if key in seen:
            existing = seen[key]
            # Merge schemes
            for scheme in target.schemes:
                if scheme not in existing.schemes:
                    existing.schemes.append(scheme)
            # Merge port hints
            for port in target.port_hints:
                if port not in existing.port_hints:
                    existing.port_hints.append(port)
            logger.debug(
                "Deduplicated %s → %s", target.original_input, existing.original_input
            )
        else:
            seen[key] = target
            result.append(target)

    return result


def parse_targets(entries: List[str]) -> List[Target]:
    """Parse a mixed list of target strings into normalized Target objects.

    Handles: IPv4, IPv6, CIDR, dash ranges, hostnames, subdomains, full URLs.
    CIDR and dash ranges are streamed as generators to avoid memory issues.
    Performs DNS resolution and deduplication.

    Args:
        entries: List of raw target strings (may be 200+ mixed formats).

    Returns:
        Deduplicated list of Target objects ready for scanning.
    """
    raw_targets: List[Target] = []

    for raw in entries:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue

        entry_type = _detect_type(entry)
        logger.debug("Parsed %r as type=%s", entry, entry_type)

        if entry_type == "ipv4":
            raw_targets.append(_build_ip_target(entry, entry, "ipv4"))

        elif entry_type == "ipv6":
            raw_targets.append(_build_ip_target(entry, entry, "ipv6"))

        elif entry_type == "cidr":
            for host_ip in _generate_cidr_hosts(entry):
                raw_targets.append(_build_ip_target(host_ip, entry, "cidr"))

        elif entry_type == "dash_range":
            for host_ip in _generate_dash_range_hosts(entry):
                raw_targets.append(_build_ip_target(host_ip, entry, "dash_range"))

        elif entry_type == "hostname":
            raw_targets.append(_build_hostname_target(entry, entry, "hostname"))

        elif entry_type == "url":
            raw_targets.append(_build_url_target(entry))

        elif entry_type == "unknown":
            # Try hostname resolution as a last resort
            logger.warning("Unknown target type for %r, attempting hostname resolution", entry)
            ip = _resolve_hostname(entry)
            if ip:
                raw_targets.append(
                    Target(
                        original_input=entry,
                        type="hostname",
                        ip=ip,
                        hostname=entry,
                        schemes=["http", "https"],
                        port_hints=[80, 443],
                        status="pending",
                    )
                )
            else:
                raw_targets.append(
                    Target(
                        original_input=entry,
                        type="unknown",
                        ip=None,
                        hostname=entry,
                        schemes=[],
                        port_hints=[],
                        status="unresolvable",
                    )
                )

    logger.info("Parsed %d raw targets before deduplication", len(raw_targets))
    deduplicated = _deduplicate_targets(raw_targets)
    logger.info("After deduplication: %d unique targets", len(deduplicated))
    return deduplicated


def parse_targets_from_file(filepath: str) -> List[Target]:
    """Read target entries from a file (one per line) and parse them.

    Args:
        filepath: Path to the file containing targets.

    Returns:
        List of deduplicated Target objects.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]
        return parse_targets(lines)
    except OSError as exc:
        logger.error("Failed to read targets file %s: %s", filepath, exc)
        return []
