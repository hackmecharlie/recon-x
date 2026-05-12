# ============================================================
# RECON-X | reporting/charts.py
# Description: Generate Chart.js configuration dicts for use
#              in the HTML report template
# ============================================================

import json
from typing import Any, Dict, List

from engine.findings import ScanResult
from engine.severity import count_by_category, count_by_severity, top_vulnerable_hosts

_SEVERITY_COLORS = {
    "Critical": "#DC2626",
    "High": "#EA580C",
    "Medium": "#D97706",
    "Low": "#65A30D",
    "Informational": "#6B7280",
}


def severity_pie_config(scan_result: ScanResult) -> Dict[str, Any]:
    """Generate Chart.js pie chart config for findings by severity.

    Args:
        scan_result: Completed ScanResult.

    Returns:
        Chart.js configuration dict.
    """
    counts = count_by_severity(scan_result.all_findings)
    labels = [k for k, v in counts.items() if v > 0]
    data = [counts[k] for k in labels]
    colors = [_SEVERITY_COLORS[k] for k in labels]

    return {
        "type": "doughnut",
        "data": {
            "labels": labels,
            "datasets": [{
                "data": data,
                "backgroundColor": colors,
                "borderColor": "#0F172A",
                "borderWidth": 3,
                "hoverBorderWidth": 4,
            }],
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "plugins": {
                "legend": {
                    "position": "right",
                    "labels": {
                        "color": "#F1F5F9",
                        "font": {"family": "Inter", "size": 13},
                        "padding": 16,
                        "usePointStyle": True,
                    },
                },
                "tooltip": {
                    "backgroundColor": "#1E293B",
                    "borderColor": "#334155",
                    "borderWidth": 1,
                    "titleColor": "#F1F5F9",
                    "bodyColor": "#94A3B8",
                    "callbacks": {
                        "label": "function(ctx){return ' '+ctx.label+': '+ctx.parsed+' findings';}"
                    },
                },
            },
            "cutout": "55%",
            "animation": {"duration": 800, "easing": "easeInOutQuart"},
        },
    }


def category_bar_config(scan_result: ScanResult) -> Dict[str, Any]:
    """Generate Chart.js bar chart config for findings by category.

    Args:
        scan_result: Completed ScanResult.

    Returns:
        Chart.js configuration dict.
    """
    counts = count_by_category(scan_result.all_findings)
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    labels = [item[0] for item in sorted_items]
    data = [item[1] for item in sorted_items]

    # Gradient colors based on rank
    bar_colors = [
        "#3B82F6",
        "#6366F1",
        "#8B5CF6",
        "#A855F7",
        "#EC4899",
        "#EF4444",
        "#F97316",
        "#EAB308",
        "#22C55E",
        "#14B8A6",
    ]
    colors = [bar_colors[i % len(bar_colors)] for i in range(len(labels))]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [{
                "label": "Findings",
                "data": data,
                "backgroundColor": colors,
                "borderRadius": 6,
                "borderSkipped": False,
            }],
        },
        "options": {
            "responsive": True,
            "maintainAspectRatio": False,
            "plugins": {
                "legend": {"display": False},
                "tooltip": {
                    "backgroundColor": "#1E293B",
                    "borderColor": "#334155",
                    "borderWidth": 1,
                    "titleColor": "#F1F5F9",
                    "bodyColor": "#94A3B8",
                },
            },
            "scales": {
                "x": {
                    "ticks": {"color": "#94A3B8", "font": {"family": "Inter"}},
                    "grid": {"color": "#1E293B", "drawBorder": False},
                },
                "y": {
                    "beginAtZero": True,
                    "ticks": {"color": "#94A3B8", "font": {"family": "Inter"}, "stepSize": 1},
                    "grid": {"color": "#334155", "drawBorder": False},
                },
            },
            "animation": {"duration": 600},
        },
    }


def host_bar_config(scan_result: ScanResult, top_n: int = 10) -> Dict[str, Any]:
    """Generate horizontal bar chart for top most vulnerable hosts.

    Args:
        scan_result: Completed ScanResult.
        top_n: Number of top hosts to include.

    Returns:
        Chart.js configuration dict.
    """
    top_hosts = top_vulnerable_hosts(scan_result, top_n)
    labels = [h["host"] for h in top_hosts]
    scores = [h["risk_score"] for h in top_hosts]
    counts = [h["finding_count"] for h in top_hosts]

    # Color code by risk score
    def score_color(score: float) -> str:
        if score >= 30:
            return "#DC2626"
        elif score >= 15:
            return "#EA580C"
        elif score >= 5:
            return "#D97706"
        return "#65A30D"

    bar_colors = [score_color(s) for s in scores]

    return {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [{
                "label": "Risk Score",
                "data": scores,
                "backgroundColor": bar_colors,
                "borderRadius": 4,
                "borderSkipped": False,
            }],
        },
        "options": {
            "indexAxis": "y",
            "responsive": True,
            "maintainAspectRatio": False,
            "plugins": {
                "legend": {"display": False},
                "tooltip": {
                    "backgroundColor": "#1E293B",
                    "borderColor": "#334155",
                    "borderWidth": 1,
                    "titleColor": "#F1F5F9",
                    "bodyColor": "#94A3B8",
                    "callbacks": {
                        "afterBody": f"function(ctx){{var idx=ctx[0].dataIndex; var c={json.dumps(counts)}; return 'Findings: '+c[idx];}}"
                    },
                },
            },
            "scales": {
                "x": {
                    "beginAtZero": True,
                    "ticks": {"color": "#94A3B8", "font": {"family": "Inter"}},
                    "grid": {"color": "#334155", "drawBorder": False},
                },
                "y": {
                    "ticks": {
                        "color": "#F1F5F9",
                        "font": {"family": "IBM Plex Mono", "size": 11},
                    },
                    "grid": {"display": False},
                },
            },
            "animation": {"duration": 600},
        },
    }


def charts_to_json(scan_result: ScanResult) -> str:
    """Serialize all chart configurations to a JSON string.

    Args:
        scan_result: Completed ScanResult.

    Returns:
        JSON string with all chart configurations.
    """
    return json.dumps({
        "severity_pie": severity_pie_config(scan_result),
        "category_bar": category_bar_config(scan_result),
        "host_bar": host_bar_config(scan_result),
    })
