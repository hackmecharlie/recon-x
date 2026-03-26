# ============================================================
# RECON-X | cli/prompts.py
# Description: Interactive CLI prompts, ASCII banner, scan title
#              suggestions, and target confirmation dialogs
# ============================================================

import csv
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

console = Console()

_ASCII_BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝
"""


def print_banner() -> None:
    """Print the RECON-X ASCII art banner with version info."""
    text = Text(_ASCII_BANNER, style="bold blue")
    console.print(text)
    console.print(
        "  [bold cyan]RECON-X[/] [dim]v1.0.0[/]  —  "
        "[dim]Automated Security Reconnaissance Tool[/]\n"
        "  [dim]──────────────────────────────────────────────────────────[/]\n"
    )


def get_scan_title(provided: Optional[str] = None) -> str:
    """Get or prompt for a scan report title.

    If provided is not None, returns it directly.
    Otherwise, shows contextual suggestions and prompts interactively.

    Args:
        provided: Pre-supplied title (from --title flag).

    Returns:
        Scan title string.
    """
    if provided:
        return provided

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M")
    hour = now.hour

    if hour < 6:
        period = "Night"
    elif hour < 12:
        period = "Morning"
    elif hour < 17:
        period = "Afternoon"
    elif hour < 21:
        period = "Evening"
    else:
        period = "Night"

    # Generate contextual suggestions based on time and day
    weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    weekday = weekday_names[now.weekday()]

    suggestions = [
        f"{period} Recon {date_str}",
        f"{weekday} Security Scan {date_str}",
        f"Network Assessment {date_str} {time_str}",
        f"Compliance Audit {date_str}",
        f"Vulnerability Scan {date_str}",
    ]

    console.print("[bold]📋 Scan Report Title[/]")
    console.print("[dim]Choose a descriptive title for your security assessment:[/]")
    console.print()
    console.print("[bold cyan]Suggestions:[/]")
    for i, sug in enumerate(suggestions, 1):
        console.print(f"  [cyan]{i}.[/] {sug}")
    console.print()
    console.print("[dim]💡 Tip: Use descriptive titles for better report organization[/]")
    console.print()

    title = Prompt.ask(
        "[bold]Enter title[/] [dim](or press Enter for suggestion 1)[/]",
        default=suggestions[0],
    )
    return title.strip() or suggestions[0]


def get_targets(
    provided_targets: Optional[str] = None,
    input_file: Optional[str] = None,
) -> List[str]:
    """Get target list from flags or interactive prompt.

    Args:
        provided_targets: Comma-separated inline targets or path to targets file.
        input_file: Path to a targets file (TXT or CSV).

    Returns:
        List of raw target strings.
    """
    if provided_targets:
        # Check if provided_targets is a file path
        targets_path = Path(provided_targets)
        if targets_path.exists():
            # It's a file path, read from file
            try:
                if targets_path.suffix.lower() == '.csv':
                    # Parse CSV file, assume targets in first column
                    targets = []
                    with open(targets_path, 'r', encoding='utf-8', newline='') as fh:
                        reader = csv.reader(fh)
                        for row in reader:
                            if row and row[0].strip():
                                targets.append(row[0].strip())
                    return targets
                else:
                    # Parse TXT file (one per line)
                    with open(targets_path, "r", encoding="utf-8") as fh:
                        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
            except OSError as exc:
                console.print(f"[red]Error reading {provided_targets}: {exc}[/]")
                return []
        else:
            # Not a file, treat as comma-separated targets
            return [t.strip() for t in provided_targets.split(",") if t.strip()]

    if input_file:
        file_path = Path(input_file)
        if not file_path.exists():
            console.print(f"[red]File not found: {input_file}[/]")
            return []

        try:
            if file_path.suffix.lower() == '.csv':
                # Parse CSV file, assume targets in first column
                targets = []
                with open(file_path, 'r', encoding='utf-8', newline='') as fh:
                    reader = csv.reader(fh)
                    for row in reader:
                        if row and row[0].strip():
                            targets.append(row[0].strip())
                return targets
            else:
                # Parse TXT file (one per line)
                with open(file_path, "r", encoding="utf-8") as fh:
                    return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError as exc:
            console.print(f"[red]Error reading {input_file}: {exc}[/]")
            return []

    # Interactive prompt with enhanced help
    console.print("[bold]🎯 Target Input[/]")
    console.print("[dim]RECON-X supports multiple target formats for comprehensive scanning:[/]")
    console.print()

    # Show format examples
    console.print("[bold cyan]Supported Formats:[/]")
    console.print("  [green]•[/] [bold]IP Addresses:[/] 192.168.1.1, 10.0.0.50")
    console.print("  [green]•[/] [bold]CIDR Ranges:[/] 192.168.1.0/24, 10.0.0.0/16")
    console.print("  [green]•[/] [bold]IP Ranges:[/] 192.168.1.1-192.168.1.255")
    console.print("  [green]•[/] [bold]Hostnames:[/] api.example.com, internal.corp.local")
    console.print("  [green]•[/] [bold]URLs:[/] https://webapp.corp.com, http://admin.internal:8080")
    console.print("  [green]•[/] [bold]Files:[/] targets.txt, targets.csv (use --input flag)")
    console.print()

    # Show usage examples
    console.print("[bold cyan]Usage Examples:[/]")
    console.print("  [dim]Single target:[/] 192.168.1.100")
    console.print("  [dim]Multiple IPs:[/] 192.168.1.1, 192.168.1.2, 10.0.0.50")
    console.print("  [dim]Network range:[/] 192.168.1.0/24")
    console.print("  [dim]Web applications:[/] https://portal.corp.com, api.internal.com")
    console.print("  [dim]Mixed targets:[/] 192.168.1.0/24, api.example.com, https://web.corp.com")
    console.print()

    # Show file format examples
    console.print("[bold cyan]File Input Formats:[/]")
    console.print("  [dim]TXT file (targets.txt):[/]")
    console.print("    [green]192.168.1.1[/]")
    console.print("    [green]192.168.1.2[/]")
    console.print("    [green]# This is a comment[/]")
    console.print("    [green]api.example.com[/]")
    console.print()
    console.print("  [dim]CSV file (targets.csv):[/]")
    console.print("    [green]192.168.1.1,Web Server,Production[/]")
    console.print("    [green]api.example.com,API Gateway,Development[/]")
    console.print()

    raw = Prompt.ask("[bold]Enter targets[/] [dim](comma-separated or one per line)[/]")
    entries: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            entries.append(part)
    return entries


def confirm_scan(
    title: str,
    targets: List[str],
    profile: str,
    concurrency: int,
    output_dir: str,
    no_screenshots: bool,
    no_cve: bool,
    ports_only: bool = False,
    smb_only: bool = False,
    web_only: bool = False,
    tls_only: bool = False,
    screenshots_only: bool = False,
) -> bool:
    """Display scan configuration summary and ask for confirmation.

    Args:
        title: Scan title.
        targets: List of target strings.
        profile: Scan profile name.
        concurrency: Max concurrent workers.
        output_dir: Output directory path.
        no_screenshots: Whether screenshots are disabled.
        no_cve: Whether CVE lookup is disabled.
        ports_only: Only perform port scanning.
        smb_only: Only perform SMB scanning.
        web_only: Only perform web scanning.
        tls_only: Only perform TLS scanning.
        screenshots_only: Only capture screenshots.

    Returns:
        True if user confirms, False otherwise.
    """
    # Determine scan type and description
    if ports_only:
        scan_type = "Port Scanning Only"
        scan_desc = "• Port discovery and service enumeration\n• No vulnerability assessment"
    elif smb_only:
        scan_type = "SMB Scanning Only"
        scan_desc = "• SMB service detection and vulnerability checks\n• Requires open SMB ports (445/139)"
    elif web_only:
        scan_type = "Web Scanning Only"
        scan_desc = "• HTTP security headers analysis\n• Clickjacking vulnerability detection\n• Requires open web ports (80/443/8080/etc.)"
    elif tls_only:
        scan_type = "TLS Scanning Only"
        scan_desc = "• SSL/TLS certificate validation\n• Cipher suite analysis\n• HSTS header checking"
    elif screenshots_only:
        scan_type = "Screenshots Only"
        scan_desc = "• Web interface screenshots\n• Visual reconnaissance only"
    else:
        scan_type = "Full Assessment"
        scan_desc = "• Complete security reconnaissance\n• Port scanning + service analysis\n• Vulnerability detection\n• Web security checks\n• SMB enumeration\n• TLS analysis"

    # Profile description
    if profile == "quick":
        profile_desc = "Top 100 ports, basic detection (fastest)"
    elif profile == "normal":
        profile_desc = "Top 1000 ports, service versions, scripts (balanced)"
    elif profile == "full":
        profile_desc = "Top 5000 ports, OS detection, vuln scripts (thorough)"
    else:
        profile_desc = f"Custom profile: {profile}"

    console.print()
    panel_content = (
        f"[bold cyan]Scan Configuration[/]\n\n"
        f"  [dim]Title:[/]          [bold]{title}[/]\n"
        f"  [dim]Targets:[/]        [bold]{len(targets)}[/] entries\n"
        f"  [dim]Scan Type:[/]      [bold cyan]{scan_type}[/]\n"
        f"  [dim]Profile:[/]        [bold cyan]{profile.upper()}[/] [dim]({profile_desc})[/]\n"
        f"  [dim]Concurrency:[/]    [bold]{concurrency}[/] parallel targets\n"
        f"  [dim]Output:[/]         [bold]{output_dir}[/]\n"
        f"  [dim]Screenshots:[/]    {'[red]DISABLED[/]' if no_screenshots else '[green]ENABLED[/]'}\n"
        f"  [dim]CVE Lookup:[/]     {'[red]DISABLED[/]' if no_cve else '[green]ENABLED[/]'}\n\n"
        f"[bold cyan]Scan Scope:[/]\n{scan_desc}"
    )

    console.print(Panel.fit(
        panel_content,
        border_style="blue",
        title="[bold]🔍 RECON-X Security Scan[/]",
    ))

    # Show estimated time if possible
    if not any([ports_only, smb_only, web_only, tls_only, screenshots_only]):
        # Rough estimation for full scans
        if profile == "quick":
            est_time = len(targets) * 0.5  # 30 seconds per target
        elif profile == "normal":
            est_time = len(targets) * 2  # 2 minutes per target
        else:  # full
            est_time = len(targets) * 5  # 5 minutes per target

        est_time = est_time / concurrency  # Adjust for parallelism
        if est_time < 1:
            time_str = f"~{est_time*60:.0f} seconds"
        elif est_time < 60:
            time_str = f"~{est_time:.1f} minutes"
        else:
            time_str = f"~{est_time/60:.1f} hours"

        console.print(f"[dim]⏱️  Estimated scan time: {time_str} (with {concurrency} parallel targets)[/]")
    console.print()

    return Confirm.ask("[bold]🚀 Proceed with scan?[/]", default=True)


def prompt_resume(checkpoint_info: dict) -> bool:
    """Ask if the user wants to resume an incomplete scan.

    Args:
        checkpoint_info: Dict with keys: title, started_at,
                         completed, total.

    Returns:
        True if user wants to resume.
    """
    completed = len(checkpoint_info.get("completed", []))
    total = checkpoint_info.get("total_targets", 0)
    title = checkpoint_info.get("title", "Unknown")
    started = checkpoint_info.get("started_at", "Unknown")

    console.print()
    console.print(
        f"[bold yellow]⚠  Incomplete scan found:[/] [bold]{title}[/] "
        f"([dim]{started[:10]}[/])\n"
        f"   [dim]Completed:[/] {completed}/{total} targets"
    )
    return Confirm.ask("[bold]Resume?[/]", default=True)
