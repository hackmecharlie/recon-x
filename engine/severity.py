# ============================================================
# RECON-X | engine/severity.py
# Description: CVSS v3 base scores, severity calculations,
#              and overall scan risk rating utilities
# ============================================================

from typing import Dict, List

from engine.findings import Finding, ScanResult, SeverityLevel

# CVSS v3 base scores assigned to common finding types
_FINDING_BASE_SCORES: Dict[str, float] = {
    # Critical
    "SMB Null Session": 9.8,
    "SMBv1 Protocol Enabled": 9.8,
    "EternalBlue Conditions Detected": 9.8,
    "MS17-010 Vulnerability": 9.8,
    "VNC No Authentication Required": 9.8,
    "SSL 2.0 Accepted": 9.0,
    "SSL 3.0 Accepted (POODLE)": 9.0,
    "NULL Cipher Accepted": 9.5,
    "EXPORT Cipher Accepted": 9.1,
    "Anonymous Cipher Accepted": 9.0,
    "BlueKeep Conditions Detected": 9.8,
    "TLS Certificate Expired": 9.0,
    "TLS Certificate Hostname Mismatch": 9.0,
    "Weak Certificate Signature (MD5)": 9.0,
    # High
    "SMB Guest Access Enabled": 8.1,
    "SMB Signing Not Required": 7.4,
    "TLS 1.0 Accepted": 7.4,
    "RC4 Cipher Accepted": 7.4,
    "DES/3DES Cipher Accepted (SWEET32)": 7.5,
    "TLS Certificate Expiring Soon (<30d)": 7.0,
    "Weak RSA Key Size (<2048 bits)": 7.5,
    "Weak Certificate Signature (SHA1)": 7.4,
    "Telnet Enabled - Cleartext Protocol": 8.1,
    "VNC Weak Authentication": 7.5,
    "RDP No NLA Enforced": 7.5,
    # Medium
    "TLS 1.1 Accepted": 5.9,
    "HSTS Header Missing": 5.4,
    "HSTS max-age Too Short": 4.3,
    "Content-Security-Policy Missing": 5.4,
    "X-Frame-Options Missing": 5.4,
    "Clickjacking Protection Missing": 5.4,
    "BEAST Attack Conditions": 5.9,
    "RDP Exposed to Network": 5.3,
    "Incomplete Certificate Chain": 5.4,
    # Low
    "TLS 1.1 Accepted": 3.7,
    "X-Content-Type-Options Missing": 3.1,
    "Referrer-Policy Missing": 3.1,
    "Permissions-Policy Missing": 3.1,
    "Server Header Disclosed": 3.1,
    "X-Powered-By Disclosed": 3.1,
    "TLS Certificate Expiring Soon (<90d)": 3.7,
    "X-AspNet-Version Disclosed": 3.1,
    "Wildcard Certificate": 2.0,
    # Informational
    "Via Header Present": 0.0,
    "X-Drupal-Cache Present": 0.0,
    "TLS Certificate Wildcard": 0.0,
}

# Severity thresholds for CVSS scores
_SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Informational"),
]

# Weights for overall risk score calculation
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "Critical": 10.0,
    "High": 5.0,
    "Medium": 2.0,
    "Low": 1.0,
    "Informational": 0.0,
}


def cvss_to_severity(score: float) -> SeverityLevel:
    """Map a CVSS v3 base score to a severity level.

    Args:
        score: CVSS v3 score between 0.0 and 10.0.

    Returns:
        Severity level string.
    """
    for threshold, level in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return level  # type: ignore[return-value]
    return "Informational"


def get_base_score(finding_title: str) -> float:
    """Look up the assigned CVSS base score for a finding type.

    Args:
        finding_title: The exact finding title string.

    Returns:
        CVSS base score, defaulting to 0.0 if unknown.
    """
    return _FINDING_BASE_SCORES.get(finding_title, 0.0)


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    """Count findings grouped by severity level.

    Args:
        findings: List of Finding objects.

    Returns:
        Dict mapping severity level to count.
    """
    counts: Dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def count_by_category(findings: List[Finding]) -> Dict[str, int]:
    """Count findings grouped by category.

    Args:
        findings: List of Finding objects.

    Returns:
        Dict mapping category name to count.
    """
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return counts


def compute_risk_score(findings: List[Finding]) -> float:
    """Compute an overall risk score (0-100) from a list of findings.

    Formula: Critical×10 + High×5 + Medium×2 + Low×1, capped at 100.

    Args:
        findings: List of Finding objects.

    Returns:
        Risk score between 0 and 100.
    """
    counts = count_by_severity(findings)
    raw_score = sum(
        counts.get(level, 0) * weight
        for level, weight in _SEVERITY_WEIGHTS.items()
    )
    return min(raw_score, 100.0)


def overall_risk_rating(findings: List[Finding]) -> str:
    """Determine the overall risk rating based on findings.

    Returns the highest severity level present, or "Clean" if none.

    Args:
        findings: List of Finding objects.

    Returns:
        One of: "Critical", "High", "Medium", "Low", "Clean"
    """
    counts = count_by_severity(findings)
    for level in ("Critical", "High", "Medium", "Low"):
        if counts.get(level, 0) > 0:
            return level
    return "Clean"


def top_vulnerable_hosts(scan_result: ScanResult, n: int = 10) -> List[Dict]:
    """Return the top N most vulnerable hosts by weighted finding count.

    Args:
        scan_result: Completed ScanResult.
        n: Number of hosts to return.

    Returns:
        List of dicts with host, count, and score, sorted descending.
    """
    host_scores: Dict[str, Dict] = {}

    for tr in scan_result.target_results:
        host = tr.target.display_name
        counts = tr.finding_counts
        score = tr.risk_score
        host_scores[host] = {
            "host": host,
            "finding_count": len(tr.findings),
            "risk_score": score,
            "counts": counts,
        }

    return sorted(
        host_scores.values(),
        key=lambda x: x["risk_score"],
        reverse=True,
    )[:n]
