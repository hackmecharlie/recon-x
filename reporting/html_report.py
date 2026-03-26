# ============================================================
# RECON-X | reporting/html_report.py
# Description: Generate a self-contained HTML report from scan
#              results using Jinja2 templates
# ============================================================

import base64
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from engine.findings import ScanResult
from engine.severity import (
    count_by_category,
    count_by_severity,
    compute_risk_score,
    top_vulnerable_hosts,
)
from reporting.charts import charts_to_json

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _encode_screenshot(path: str) -> str:
    """Base64-encode a screenshot for embedding in HTML.

    Args:
        path: File path to the PNG screenshot.

    Returns:
        Data URI string for the image.
    """
    try:
        data = Path(path).read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except (OSError, Exception) as exc:
        logger.debug("Failed to encode screenshot %s: %s", path, exc)
        return ""


def _build_headers_summary(header_findings: list) -> Dict[str, Any]:
    """Build a summary of security headers from findings.

    Args:
        header_findings: List of findings related to web headers.

    Returns:
        Dict with security_headers, info_disclosure, and statistics.
    """
    security_headers = {
        "present": [],
        "missing": [],
        "wrongly_configured": [],
    }

    info_disclosure_headers = {
        "present": [],
    }

    # Categorize findings
    for finding in header_findings:
        title = finding.title
        severity = finding.severity
        target = finding.target

        # Information disclosure headers
        if "Disclosed" in title:
            info_disclosure_headers["present"].append({
                "header": title.replace(" Header Disclosed", ""),
                "severity": severity,
                "value_hint": finding.description,
                "target": target,
            })
        # Missing headers
        elif "Missing" in title:
            security_headers["missing"].append({
                "header": title.replace(" Header Missing", ""),
                "severity": severity,
                "description": finding.description,
                "target": target,
            })
        # Wrongly configured
        elif "ALLOWALL" in title or "Not Restrictive" in title:
            security_headers["wrongly_configured"].append({
                "header": title,
                "severity": severity,
                "description": finding.description,
                "target": target,
            })

    return {
        "security_headers": security_headers,
        "info_disclosure_headers": info_disclosure_headers,
        "total_security_issues": len(security_headers["missing"]) + len(security_headers["wrongly_configured"]),
        "total_info_disclosure": len(info_disclosure_headers["present"]),
    }


def _build_template_context(scan_result: ScanResult) -> Dict[str, Any]:
    """Build the Jinja2 template context from a ScanResult.

    Args:
        scan_result: Completed ScanResult to report on.

    Returns:
        Dict with all template variables.
    """
    severity_counts = count_by_severity(scan_result.all_findings)
    category_counts = count_by_category(scan_result.all_findings)
    risk_score = compute_risk_score(scan_result.all_findings)
    top_hosts = top_vulnerable_hosts(scan_result, 10)

    # Sort findings by severity
    severity_order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    sorted_findings = sorted(
        scan_result.all_findings,
        key=lambda f: severity_order.get(f.severity, 99),
    )

    # Top 5 critical findings for executive summary
    top_findings = sorted_findings[:5]

    # Build target status list for appendix
    target_statuses = []
    for tr in scan_result.target_results:
        target_statuses.append({
            "host": tr.target.display_name,
            "ip": tr.target.ip or "",
            "status": tr.status,
            "duration": f"{(tr.scan_end - tr.scan_start).total_seconds():.1f}s",
            "open_ports": len(tr.open_ports),
            "findings": len(tr.findings),
        })

    # Embed screenshots if enabled
    all_screenshots = []
    for tr in scan_result.target_results:
        for ss in tr.screenshots:
            encoded = ""
            if ss.screenshot_path:
                encoded = _encode_screenshot(ss.screenshot_path)
            all_screenshots.append({
                "host": ss.host,
                "scheme": ss.scheme,
                "port": ss.port,
                "final_url": ss.final_url,
                "page_title": ss.page_title,
                "status_code": ss.status_code,
                "encoded_image": encoded,
                "error": ss.error,
            })

    # Build certificate table data
    cert_data = []
    for tr in scan_result.target_results:
        if tr.cert_result:
            c = tr.cert_result
            cert_data.append({
                "host": c.host,
                "port": c.port,
                "cn": c.subject_cn,
                "issuer": c.issuer_cn,
                "expiry": c.valid_until or "",
                "days_left": c.days_until_expiry,
                "sans_count": len(c.sans),
                "issues": len([f for f in c.findings if f.severity in ("Critical", "High")]),
                "self_signed": c.is_self_signed,
                "expired": c.is_expired,
            })

    # Port scan accordion data
    port_data = []
    for tr in scan_result.target_results:
        if tr.open_ports:
            port_data.append({
                "host": tr.target.display_name,
                "ports": [
                    {
                        "port": p.port_number,
                        "proto": p.protocol,
                        "service": p.service_name,
                        "version": f"{p.product} {p.service_version}".strip(),
                        "banner": (p.banner or "")[:80],
                    }
                    for p in tr.open_ports
                ],
            })

    # Build security headers summary from findings
    header_findings = [
        f for f in scan_result.all_findings
        if f.category == "Web Headers"
    ]
    headers_summary = _build_headers_summary(header_findings)

    scan_duration = scan_result.duration_seconds
    hours, remainder = divmod(int(scan_duration), 3600)
    minutes, seconds = divmod(remainder, 60)
    duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    return {
        "scan_id": scan_result.scan_id,
        "title": scan_result.title,
        "profile": scan_result.profile,
        "output_dir": scan_result.output_dir,
        "started_at": scan_result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "finished_at": (scan_result.finished_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration": duration_str,
        "total_targets": scan_result.total_targets,
        "alive_targets": scan_result.alive_targets,
        "total_findings": len(scan_result.all_findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "risk_score": f"{risk_score:.1f}",
        "overall_risk": scan_result.overall_risk,
        "top_findings": top_findings,
        "top_hosts": top_hosts,
        "all_findings": sorted_findings,
        "target_results": scan_result.target_results,
        "target_statuses": target_statuses,
        "screenshots": all_screenshots,
        "cert_data": cert_data,
        "port_data": port_data,
        "headers_summary": headers_summary,
        "charts_json": charts_to_json(scan_result),
        "severity_order": _SEVERITY_ORDER,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool_version": "1.0.0",
    }


def generate_html_report(scan_result: ScanResult, output_path: Optional[str] = None) -> str:
    """Generate a self-contained HTML report.

    Args:
        scan_result: Completed ScanResult.
        output_path: Optional override for output file path.

    Returns:
        Path to the generated HTML file.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )

    # Register custom filters
    env.filters["severity_color"] = lambda s: {
        "Critical": "#DC2626",
        "High": "#EA580C",
        "Medium": "#D97706",
        "Low": "#65A30D",
        "Informational": "#6B7280",
    }.get(s, "#6B7280")

    env.filters["severity_bg"] = lambda s: {
        "Critical": "bg-red-900/50 text-red-300 border-red-700",
        "High": "bg-orange-900/50 text-orange-300 border-orange-700",
        "Medium": "bg-yellow-900/50 text-yellow-300 border-yellow-700",
        "Low": "bg-green-900/50 text-green-300 border-green-700",
        "Informational": "bg-gray-700/50 text-gray-300 border-gray-600",
    }.get(s, "bg-gray-700 text-gray-300")

    try:
        template = env.get_template("report_enhanced.html.j2")
    except Exception as exc:
        logger.error("Failed to load template: %s", exc)
        raise

    context = _build_template_context(scan_result)

    try:
        rendered = template.render(**context)
    except Exception as exc:
        logger.error("Template rendering failed: %s", exc)
        raise

    if output_path is None:
        output_path = str(Path(scan_result.output_dir) / "report.html")

    Path(output_path).write_text(rendered, encoding="utf-8")
    logger.info("HTML report saved to %s", output_path)
    return output_path
