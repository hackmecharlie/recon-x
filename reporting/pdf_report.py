# ============================================================
# RECON-X | reporting/pdf_report.py
# Description: Render Jinja2 template to PDF via WeasyPrint
#              with page headers, footers, and proper pagination
# ============================================================

import logging
from pathlib import Path
from typing import Optional

from engine.findings import ScanResult
from reporting.html_report import _build_template_context, _TEMPLATES_DIR

logger = logging.getLogger(__name__)

_PDF_CSS = """
/* Professional PDF styling for RECON-X reports */

/* ============================================
   Page Setup & Typography
   ============================================ */
@page {
    size: A4;
    margin: 1in;
}

body {
    font-family: 'Segoe UI', 'Helvetica', 'Arial', sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #1F2937;
}

/* ============================================
   Headings & Hierarchy
   ============================================ */
h1 {
    font-size: 28pt;
    font-weight: 700;
    color: #1F2937;
    margin: 0 0 24pt 0;
    border-bottom: 3pt solid #3B82F6;
    padding-bottom: 12pt;
}

h2 {
    font-size: 18pt;
    font-weight: 700;
    color: #1F2937;
    margin: 28pt 0 14pt 0;
    border-bottom: 2pt solid #3B82F6;
    padding-bottom: 8pt;
    page-break-after: avoid;
}

h3 {
    font-size: 14pt;
    font-weight: 600;
    color: #374151;
    margin: 20pt 0 10pt 0;
    page-break-after: avoid;
}

h4 {
    font-size: 12pt;
    font-weight: 600;
    color: #374151;
    margin: 14pt 0 8pt 0;
    page-break-after: avoid;
}

/* ============================================
   Professional Tables
   ============================================ */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 14pt 0;
    border: 1pt solid #D1D5DB;
}

thead {
    background: linear-gradient(135deg, #1F2937 0%, #374151 100%);
    color: white;
}

thead th {
    padding: 10pt 12pt;
    font-weight: 600;
    font-size: 10pt;
    text-align: left;
    border: 1pt solid #111827;
}

tbody tr:nth-child(odd) {
    background-color: #F9FAFB;
}

tbody tr:nth-child(even) {
    background-color: #FFFFFF;
}

td {
    padding: 9pt 12pt;
    border: 1pt solid #E5E7EB;
    font-size: 10pt;
}

td.severity-Critical {
    color: #DC2626;
    font-weight: 600;
    background-color: #FEE2E2;
}

td.severity-High {
    color: #EA580C;
    font-weight: 600;
    background-color: #FFEDD5;
}

td.severity-Medium {
    color: #D97706;
    font-weight: 600;
    background-color: #FEF3C7;
}

td.severity-Low {
    color: #65A30D;
    font-weight: 600;
    background-color: #F2FDE8;
}

td.severity-Informational {
    color: #6B7280;
    font-weight: 500;
    background-color: #F3F4F6;
}

/* Stats table styling */
.stats-table tbody tr:nth-child(odd) {
    background-color: #F3F4F6;
}

.stats-table tbody tr:nth-child(even) {
    background-color: #FFFFFF;
}

.stats-table td {
    text-align: center;
    padding: 12pt;
    font-weight: 500;
}

/* ============================================
   Risk Assessment Boxes
   ============================================ */
.risk-level {
    font-size: 14pt;
    font-weight: 600;
    text-align: center;
    margin: 20pt 0;
    padding: 16pt;
    border-radius: 4pt;
    border: 2pt solid;
    page-break-inside: avoid;
}

.risk-Critical {
    color: #DC2626;
    border-color: #DC2626;
    background-color: #FEE2E2;
}

.risk-High {
    color: #EA580C;
    border-color: #EA580C;
    background-color: #FFEDD5;
}

.risk-Medium {
    color: #D97706;
    border-color: #D97706;
    background-color: #FEF3C7;
}

.risk-Low {
    color: #65A30D;
    border-color: #65A30D;
    background-color: #F2FDE8;
}

.risk-Clean {
    color: #059669;
    border-color: #059669;
    background-color: #D1FAE5;
}

/* ============================================
   Findings & Content Blocks
   ============================================ */
.finding {
    margin: 18pt 0;
    border: 1pt solid #D1D5DB;
    padding: 12pt;
    page-break-inside: avoid;
    background-color: #FFFFFF;
    border-radius: 4pt;
    box-shadow: 0 1pt 3pt rgba(0, 0, 0, 0.05);
}

.finding-header {
    background: linear-gradient(135deg, #F3F4F6 0%, #E5E7EB 100%);
    padding: 10pt;
    margin: -12pt -12pt 12pt -12pt;
    border-bottom: 2pt solid #D1D5DB;
    border-radius: 4pt 4pt 0 0;
}

.finding-title {
    font-size: 12pt;
    font-weight: 600;
    color: #1F2937;
    margin: 0 0 4pt 0;
}

.finding-meta {
    font-size: 9pt;
    color: #6B7280;
    margin: 4pt 0 0 0;
}

.finding-section {
    margin: 10pt 0;
}

.finding-label {
    font-weight: 600;
    font-size: 10pt;
    text-transform: uppercase;
    color: #374151;
    margin-bottom: 6pt;
    letter-spacing: 0.5pt;
}

/* ============================================
   Code & Preformatted Text
   ============================================ */
pre, code {
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 9pt;
    background-color: #1F2937;
    color: #F3F4F6;
    padding: 8pt;
    border: 1pt solid #111827;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 8pt 0;
    border-radius: 3pt;
    line-height: 1.3;
}

/* ============================================
   Lists & Paragraphs
   ============================================ */
ul, ol {
    margin: 10pt 0;
    padding-left: 24pt;
    line-height: 1.6;
}

li {
    margin: 6pt 0;
    page-break-inside: avoid;
}

li.severity-Critical {
    color: #DC2626;
}

li.severity-High {
    color: #EA580C;
}

li.severity-Medium {
    color: #D97706;
}

li.severity-Low {
    color: #65A30D;
}

p {
    margin: 8pt 0;
    text-align: justify;
    orphans: 3;
    widows: 3;
}

/* ============================================
   Page & Break Management
   ============================================ */
.page {
    page-break-after: always;
}

.page-break {
    page-break-before: always;
}

.no-break {
    page-break-inside: avoid;
}

tr {
    page-break-inside: avoid;
}

/* ============================================
   Cover Page Styling
   ============================================ */
.cover-page {
    text-align: center;
    page-break-after: always;
    background: linear-gradient(180deg, rgba(31, 41, 55, 0.05) 0%, rgba(59, 130, 246, 0.05) 100%);
}

.cover-title {
    font-size: 42pt;
    font-weight: 700;
    color: #1F2937;
    margin: 80pt 0 20pt 0;
    letter-spacing: 2pt;
}

.cover-subtitle {
    font-size: 18pt;
    font-weight: 400;
    color: #3B82F6;
    margin: 0 0 60pt 0;
}

.cover-meta {
    margin: 40pt auto 0;
    text-align: left;
    max-width: 450pt;
    background-color: #FFFFFF;
    padding: 20pt;
    border: 2pt solid #3B82F6;
    border-radius: 4pt;
}

.cover-meta table {
    width: 100%;
    border: none;
    margin: 0;
}

.cover-meta td {
    padding: 10pt 12pt;
    border: none;
    border-bottom: 1pt solid #E5E7EB;
}

.cover-meta td:last-child {
    border-bottom: none;
}

.cover-meta .label {
    font-weight: 600;
    color: #3B82F6;
    width: 140pt;
}

/* ============================================
   Severity Color Classes
   ============================================ */
.severity-Critical {
    color: #DC2626;
    font-weight: 600;
}

.severity-High {
    color: #EA580C;
    font-weight: 600;
}

.severity-Medium {
    color: #D97706;
    font-weight: 600;
}

.severity-Low {
    color: #65A30D;
    font-weight: 600;
}

.severity-Informational {
    color: #6B7280;
    font-weight: 500;
}

/* ============================================
   Executive Summary Box
   ============================================ */
.exec-summary {
    background-color: #F9FAFB;
    border-left: 4pt solid #3B82F6;
    padding: 14pt;
    margin: 20pt 0;
    border-radius: 4pt;
    page-break-inside: avoid;
}

/* ============================================
   Utility Classes
   ============================================ */
.clear {
    clear: both;
}

.no-margin {
    margin: 0;
}

.highlight {
    background-color: #FEF3C7;
    padding: 2pt 4pt;
    font-weight: 500;
}
"""


def generate_pdf_report(scan_result: ScanResult, output_path: Optional[str] = None) -> str:
    """Render the scan results to a PDF report.

    Args:
        scan_result: Completed ScanResult.
        output_path: Optional override for output file path.

    Returns:
        Path to the generated PDF file.

    Raises:
        ImportError: If WeasyPrint is not installed.
        RuntimeError: If rendering fails.
    """
    try:
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
    except ImportError:
        logger.error("WeasyPrint not installed — PDF generation skipped")
        raise

    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.error("Jinja2 not installed")
        raise

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )

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

    context = _build_template_context(scan_result)
    context["is_pdf"] = True  # Flag for PDF-specific template conditionals

    try:
        template = env.get_template("pdf_report.html.j2")
        html_str = template.render(**context)
    except Exception as exc:
        logger.error("Template rendering for PDF failed: %s", exc)
        raise RuntimeError(f"Template error: {exc}") from exc

    if output_path is None:
        output_path = str(Path(scan_result.output_dir) / "report.pdf")

    font_config = FontConfiguration()
    pdf_css = CSS(string=_PDF_CSS, font_config=font_config)

    try:
        html_doc = HTML(string=html_str, base_url=str(_TEMPLATES_DIR))
        html_doc.write_pdf(
            output_path,
            stylesheets=[pdf_css],
            font_config=font_config,
            presentational_hints=True,
        )
        logger.info("PDF report saved to %s", output_path)
    except Exception as exc:
        logger.error("WeasyPrint PDF generation failed: %s", exc)
        raise RuntimeError(f"PDF generation error: {exc}") from exc

    return output_path
