# ============================================================
# RECON-X | engine/findings.py
# Description: Core dataclasses for findings, ports, scan results,
#              certificates, screenshots, and banners
# ============================================================

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from core.input_parser import Target


SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]


@dataclass
class Finding:
    """A single security finding discovered during a scan."""

    title: str
    severity: SeverityLevel
    category: str
    target: str
    description: str
    evidence: str
    remediation: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    port: Optional[int] = None
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "target": self.target,
            "port": self.port,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Port:
    """An open port discovered during an nmap scan."""

    port_number: int
    protocol: str
    state: str
    service_name: str = ""
    service_version: str = ""
    product: str = ""
    extrainfo: str = ""
    banner: str = ""
    scripts_output: Dict[str, str] = field(default_factory=dict)

    def display(self) -> str:
        """Human-readable port description."""
        parts = [f"{self.port_number}/{self.protocol}"]
        if self.service_name:
            parts.append(self.service_name)
        if self.product:
            parts.append(self.product)
        if self.service_version:
            parts.append(self.service_version)
        return " ".join(parts)


@dataclass
class CertificateResult:
    """Results from TLS certificate analysis."""

    host: str
    port: int
    subject_cn: str = ""
    subject_o: str = ""
    subject_c: str = ""
    issuer_cn: str = ""
    serial: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiry: Optional[int] = None
    sans: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    chain_complete: bool = True
    raw_pem: str = ""
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScreenshotResult:
    """Result from a web screenshot capture."""

    host: str
    scheme: str
    port: int
    final_url: str = ""
    page_title: str = ""
    status_code: Optional[int] = None
    screenshot_path: str = ""
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BannerResult:
    """Raw banner grabbed from a TCP port."""

    host: str
    port: int
    banner: str = ""
    protocol_hint: str = ""
    service_version: str = ""
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TargetResult:
    """All scan results for a single target."""

    target: Target
    status: str  # scanning, completed, failed, timeout, unreachable
    scan_start: datetime
    scan_end: datetime
    open_ports: List[Port] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    cert_result: Optional[CertificateResult] = None
    screenshots: List[ScreenshotResult] = field(default_factory=list)
    banners: List[BannerResult] = field(default_factory=list)
    raw_nmap_xml: str = ""

    @property
    def finding_counts(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts: Dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def risk_score(self) -> float:
        """Weighted risk score for this target."""
        counts = self.finding_counts
        return (
            counts["Critical"] * 10
            + counts["High"] * 5
            + counts["Medium"] * 2
            + counts["Low"] * 1
        )


@dataclass
class ScanResult:
    """Aggregated results from a complete scan run."""

    scan_id: str
    title: str
    profile: str
    output_dir: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    target_results: List[TargetResult] = field(default_factory=list)
    all_findings: List[Finding] = field(default_factory=list)

    @property
    def total_targets(self) -> int:
        return len(self.target_results)

    @property
    def alive_targets(self) -> int:
        return sum(
            1
            for tr in self.target_results
            if tr.status not in ("unreachable", "timeout", "failed")
        )

    @property
    def finding_counts(self) -> Dict[str, int]:
        """Aggregate finding counts across all targets."""
        counts: Dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def overall_risk(self) -> str:
        """Overall risk rating for the entire scan."""
        counts = self.finding_counts
        if counts["Critical"] > 0:
            return "Critical"
        if counts["High"] > 0:
            return "High"
        if counts["Medium"] > 0:
            return "Medium"
        if counts["Low"] > 0:
            return "Low"
        return "Clean"

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return (datetime.utcnow() - self.started_at).total_seconds()
