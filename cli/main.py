# ============================================================
# RECON-X | cli/main.py
# Description: Typer CLI entry point with scan, resume, report,
#              and version commands
# ============================================================

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

app = typer.Typer(
    name="recon-x",
    help="""
    [bold cyan]RECON-X[/] — Automated Security Reconnaissance Tool

    [dim]A comprehensive security assessment framework for network reconnaissance,
    vulnerability detection, and compliance auditing.[/]

    [bold]Key Features:[/]
    • [green]Multi-profile scanning[/] (quick/normal/full) for different assessment depths
    • [green]Selective scanning modes[/] for targeted security testing
    • [green]Comprehensive reporting[/] with HTML/PDF outputs and interactive dashboards
    • [green]Resume capability[/] for interrupted scans
    • [green]Concurrent processing[/] for efficient large-scale assessments

    [bold]Supported Target Formats:[/]
    • IP addresses: [dim]192.168.1.1[/]
    • CIDR ranges: [dim]10.0.0.0/24[/]
    • IP ranges: [dim]192.168.1.1-192.168.1.255[/]
    • Hostnames: [dim]api.example.com[/]
    • URLs: [dim]https://shop.corp.com/admin[/]
    • File inputs: [dim]targets.txt, targets.csv[/]

    [bold]Example Usage:[/]
    [dim]recon-x scan --targets 192.168.1.0/24 --profile quick[/]
    [dim]recon-x scan --input targets.txt --profile normal --title "Monthly Audit"[/]
    [dim]recon-x scan --targets api.corp.com --tls-only[/]
    """,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

_DEFAULT_OUTPUT_DIR = "./output"
_SETTINGS_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


def _load_settings() -> dict:
    """Load configuration from settings.yaml."""
    try:
        if _SETTINGS_PATH.exists():
            return yaml.safe_load(_SETTINGS_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        pass
    return {}


def _setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure Python logging.

    Args:
        level: Logging level string.
        log_file: Optional file path for log output.
    """
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))  # type: ignore[arg-type]

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


@app.command()
def options() -> None:
    """Show all available scan options and configurations."""
    from cli.prompts import print_banner
    print_banner()

    console.print("[bold]🔧 RECON-X Scan Options & Configurations[/]")
    console.print()

    # Scan Profiles
    console.print("[bold cyan]📊 Scan Profiles:[/]")
    console.print("  [green]quick[/]     - Top 100 ports, basic service detection")
    console.print("             - Fastest option for broad network reconnaissance")
    console.print("             - Best for: Initial network mapping, large ranges")
    console.print()
    console.print("  [yellow]normal[/]   - Top 1000 ports, service versions, default scripts")
    console.print("             - Balanced speed vs. thoroughness")
    console.print("             - Best for: Standard security assessments")
    console.print()
    console.print("  [red]full[/]     - Top 5000 ports, OS detection, vulnerability scripts")
    console.print("             - Most comprehensive but slowest")
    console.print("             - Best for: In-depth security audits, compliance")
    console.print()

    # Scan Types
    console.print("[bold cyan]🎯 Scan Types:[/]")
    console.print("  [green]Full Assessment[/]     - Complete security reconnaissance")
    console.print("                        - Port scanning + all security modules")
    console.print("                        - Generates comprehensive reports")
    console.print()
    console.print("  [cyan]Selective Modes:[/]")
    console.print("    [blue]--ports-only[/]      - Port discovery and enumeration only")
    console.print("    [blue]--smb-only[/]        - SMB vulnerability assessment only")
    console.print("    [blue]--web-only[/]        - Web security checks (headers, clickjack)")
    console.print("    [blue]--tls-only[/]        - TLS/SSL certificate analysis only")
    console.print("    [blue]--screenshots-only[/] - Web interface screenshots only")
    console.print()

    # Target Formats
    console.print("[bold cyan]🎯 Target Formats:[/]")
    console.print("  [green]• IP Addresses:[/] 192.168.1.1")
    console.print("  [green]• CIDR Ranges:[/] 192.168.1.0/24")
    console.print("  [green]• IP Ranges:[/] 192.168.1.1-192.168.1.255")
    console.print("  [green]• Hostnames:[/] api.example.com")
    console.print("  [green]• URLs:[/] https://webapp.corp.com")
    console.print("  [green]• Files:[/] targets.txt, targets.csv")
    console.print()

    # Output Formats
    console.print("[bold cyan]📄 Output Formats:[/]")
    console.print("  [green]• HTML Report:[/] Interactive dashboard with findings")
    console.print("  [green]• PDF Report:[/] Professional formatted document")
    console.print("  [green]• Screenshots:[/] Web interface captures")
    console.print("  [green]• JSON Data:[/] Raw scan results for integration")
    console.print()

    # Common Use Cases
    console.print("[bold cyan]💡 Common Use Cases:[/]")
    console.print("  [yellow]Network Recon:[/]     recon-x scan -t 192.168.1.0/24 -p quick")
    console.print("  [yellow]Web App Audit:[/]     recon-x scan -t https://app.corp.com --web-only")
    console.print("  [yellow]Compliance Scan:[/]   recon-x scan --input targets.csv -p full")
    console.print("  [yellow]TLS Assessment:[/]    recon-x scan -t api.example.com --tls-only")
    console.print("  [yellow]SMB Security:[/]      recon-x scan -t 192.168.1.100 --smb-only")
    console.print()

    console.print("[dim]💡 Tip: Use 'recon-x scan --help' for detailed command options[/]")
    console.print("[dim]💡 Tip: Use 'recon-x resume' to continue interrupted scans[/]")


@app.command()
def scan(
    targets: Optional[str] = typer.Option(None, "--targets", "-t", help="""
    Target specification. Can be:
    • Comma-separated list: [dim]192.168.1.1,10.0.0.0/24,api.example.com[/]
    • Path to targets file: [dim]/path/to/targets.txt[/]
    • Single target: [dim]https://webapp.corp.com[/]
    """),
    input_file: Optional[Path] = typer.Option(None, "--input", "-i", help="""
    Input file containing targets. Supported formats:
    • [dim]TXT:[/] One target per line, comments with #
    • [dim]CSV:[/] Targets in first column
    """),
    title: Optional[str] = typer.Option(None, "--title", help="Custom report title. If not provided, interactive suggestions will be shown."),
    profile: str = typer.Option("normal", "--profile", "-p", help="""
    Scan intensity profile:
    • [green]quick:[/] Top 100 ports, basic service detection (fastest)
    • [yellow]normal:[/] Top 1000 ports, service versions, default scripts (balanced)
    • [red]full:[/] Top 5000 ports, OS detection, vulnerability scripts (thorough)
    """),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Number of parallel targets to scan simultaneously (1-50, default: 5)"),
    output_dir: str = typer.Option(_DEFAULT_OUTPUT_DIR, "--output-dir", "-o", help="Directory for scan results and reports"),
    no_screenshots: bool = typer.Option(False, "--no-screenshots", help="Disable screenshot capture to speed up scanning"),
    no_cve: bool = typer.Option(False, "--no-cve", help="Skip CVE vulnerability correlation (reduces API calls)"),
    timeout: int = typer.Option(900, "--timeout", help="Maximum seconds per target before timeout (default: 900)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip interactive confirmation prompt"),
    # Module-specific options
    ports_only: bool = typer.Option(False, "--ports-only", help="[cyan]Selective Mode:[/] Port scanning only - discover open ports and services"),
    smb_only: bool = typer.Option(False, "--smb-only", help="[cyan]Selective Mode:[/] SMB vulnerability assessment only"),
    web_only: bool = typer.Option(False, "--web-only", help="[cyan]Selective Mode:[/] Web security checks only (headers, clickjack detection)"),
    tls_only: bool = typer.Option(False, "--tls-only", help="[cyan]Selective Mode:[/] TLS/SSL certificate analysis only"),
    screenshots_only: bool = typer.Option(False, "--screenshots-only", help="[cyan]Selective Mode:[/] Screenshot capture only"),
) -> None:
    """
    Start a new security reconnaissance scan.

    [bold]Scan Types:[/]
    • [green]Full Assessment:[/] Complete security reconnaissance (default)
    • [cyan]Selective Modes:[/] Targeted scanning for specific security areas
    • [yellow]Profile-based:[/] Quick, Normal, or Full intensity levels

    [bold]Output:[/]
    • Interactive HTML report with dashboard and findings
    • Professional PDF report for documentation
    • JSON data exports for integration
    • Screenshots of web interfaces
    • Checkpoint files for resumable scans

    [bold]Examples:[/]
    [dim]# Quick network reconnaissance[/]
    [dim]recon-x scan -t 192.168.1.0/24 -p quick[/]
    [dim][/]
    [dim]# Full assessment with custom title[/]
    [dim]recon-x scan --input targets.txt --profile full --title "Q4 Security Audit"[/]
    [dim][/]
    [dim]# TLS certificate analysis only[/]
    [dim]recon-x scan -t api.corp.com --tls-only[/]
    [dim][/]
    [dim]# Resume interrupted scan[/]
    [dim]recon-x resume[/]
    """
    settings = _load_settings()
    log_cfg = settings.get("logging", {})
    _setup_logging(
        level=log_cfg.get("level", "INFO"),
        log_file=log_cfg.get("log_file"),
    )

    from cli.prompts import print_banner, get_scan_title, get_targets, confirm_scan
    print_banner()

    # Resolve title
    scan_title = get_scan_title(title)

    # Resolve targets
    raw_targets = get_targets(
        provided_targets=targets,
        input_file=str(input_file) if input_file else None,
    )
    if not raw_targets:
        console.print("[red]No targets specified. Exiting.[/]")
        raise typer.Exit(1)

    # Confirm
    if not yes:
        ok = confirm_scan(
            title=scan_title,
            targets=raw_targets,
            profile=profile,
            concurrency=concurrency,
            output_dir=output_dir,
            no_screenshots=no_screenshots,
            no_cve=no_cve,
            ports_only=ports_only,
            smb_only=smb_only,
            web_only=web_only,
            tls_only=tls_only,
            screenshots_only=screenshots_only,
        )
        if not ok:
            console.print("[dim]Scan cancelled.[/]")
            raise typer.Exit(0)

    # Run the scan
    _run_scan(
        raw_targets=raw_targets,
        scan_title=scan_title,
        profile=profile,
        concurrency=concurrency,
        output_dir=output_dir,
        no_screenshots=no_screenshots,
        no_cve=no_cve,
        timeout=timeout,
        resume_checkpoint=None,
        ports_only=ports_only,
        smb_only=smb_only,
        web_only=web_only,
        tls_only=tls_only,
        screenshots_only=screenshots_only,
    )


@app.command()
def resume(
    output_dir: str = typer.Option(_DEFAULT_OUTPUT_DIR, "--output-dir", "-o", help="Base output directory to scan for checkpoints"),
) -> None:
    """
    Resume an interrupted or failed security scan.

    [bold]How it works:[/]
    • Automatically detects incomplete scans in the output directory
    • Shows scan progress and allows resuming from the last checkpoint
    • Preserves all previous findings and continues where it left off

    [bold]When to use:[/]
    • Network interruptions during long scans
    • System crashes or power failures
    • Manual cancellation of running scans
    • Want to continue scans with different parameters

    [bold]Examples:[/]
    [dim]recon-x resume[/]                          # Resume from default output directory
    [dim]recon-x resume --output-dir ./scans[/]     # Resume from custom directory
    """
    from cli.prompts import print_banner, prompt_resume
    from core.checkpoint import scan_for_incomplete_checkpoints
    print_banner()

    checkpoints = scan_for_incomplete_checkpoints(output_dir)
    if not checkpoints:
        console.print("[yellow]No incomplete scans found in[/] " + output_dir)
        raise typer.Exit(0)

    # Show the most recent incomplete checkpoint
    scan_dir, cp_data = checkpoints[-1]
    if not prompt_resume({
        "title": cp_data.title,
        "started_at": cp_data.started_at,
        "completed": cp_data.completed,
        "total_targets": cp_data.total_targets,
    }):
        console.print("[dim]Resume cancelled.[/]")
        raise typer.Exit(0)

    # Rebuild target list from checkpoint
    all_target_keys = (
        cp_data.completed + cp_data.failed + cp_data.timeout +
        cp_data.pending + cp_data.in_progress + cp_data.skipped
    )

    _run_scan(
        raw_targets=all_target_keys,
        scan_title=cp_data.title,
        profile=cp_data.scan_profile,
        concurrency=10,
        output_dir=str(scan_dir),
        no_screenshots=False,
        no_cve=False,
        timeout=300,
        resume_checkpoint=cp_data,
    )


@app.command()
def report(
    checkpoint_dir: str = typer.Argument(..., help="Path to completed scan output directory"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html|pdf|both"),
) -> None:
    """Generate a report from a completed scan checkpoint."""
    from cli.prompts import print_banner
    print_banner()

    from core.checkpoint import CheckpointManager
    cp_mgr = CheckpointManager(checkpoint_dir)
    cp_data = cp_mgr.load()
    if not cp_data:
        console.print(f"[red]No checkpoint found in {checkpoint_dir}[/]")
        raise typer.Exit(1)

    console.print(f"[cyan]Generating report for:[/] {cp_data.title}")

    # Build a minimal ScanResult from checkpoint data
    from engine.findings import ScanResult, TargetResult, Finding
    from core.input_parser import Target
    import json

    scan_result = ScanResult(
        scan_id=cp_data.scan_id,
        title=cp_data.title,
        profile=cp_data.scan_profile,
        output_dir=checkpoint_dir,
        started_at=datetime.fromisoformat(cp_data.started_at),
        finished_at=datetime.utcnow(),
    )

    # Reconstruct findings from checkpoint
    for f_dict in cp_data.findings:
        try:
            finding = Finding(**{
                k: v for k, v in f_dict.items()
                if k in Finding.__dataclass_fields__
            })
            scan_result.all_findings.append(finding)
        except Exception:  # noqa: BLE001
            pass

    _generate_reports(scan_result, format)
    console.print(f"[green]✓ Report saved to {checkpoint_dir}[/]")


@app.command()
def version() -> None:
    """
    Show RECON-X version and system information.

    [bold]Version:[/] 1.0.0
    [bold]Features:[/] Security reconnaissance, vulnerability assessment, reporting
    [bold]Modules:[/] Port scanning, SMB analysis, Web security, TLS validation, CVE lookup
    """
    from cli.prompts import print_banner
    print_banner()
    console.print("[bold cyan]RECON-X[/] version [bold]1.0.0[/]")
    console.print(f"Python {sys.version.split()[0]}")
    console.print()
    console.print("[bold cyan]System Capabilities:[/]")
    console.print("  [green]•[/] Multi-profile scanning (quick/normal/full)")
    console.print("  [green]•[/] Selective scanning modes")
    console.print("  [green]•[/] Concurrent processing")
    console.print("  [green]•[/] Resume interrupted scans")
    console.print("  [green]•[/] HTML/PDF report generation")
    console.print("  [green]•[/] CVE vulnerability correlation")


# ── Internal helpers ─────────────────────────────────────────────────────────

def _run_scan(
    raw_targets: list,
    scan_title: str,
    profile: str,
    concurrency: int,
    output_dir: str,
    no_screenshots: bool,
    no_cve: bool,
    timeout: int,
    resume_checkpoint,
    ports_only: bool = False,
    smb_only: bool = False,
    web_only: bool = False,
    tls_only: bool = False,
    screenshots_only: bool = False,
) -> None:
    """Orchestrate a complete scan run.

    Args:
        raw_targets: List of raw target strings or keys.
        scan_title: Title for the report.
        profile: Scan profile name.
        concurrency: Max parallel workers.
        output_dir: Base output directory.
        no_screenshots: Disable screenshot module.
        no_cve: Disable CVE lookup.
        timeout: Per-target timeout in seconds.
        resume_checkpoint: Optional CheckpointData to resume from.
        ports_only: Only perform port scanning.
        smb_only: Only perform SMB scanning.
        web_only: Only perform web scanning.
        tls_only: Only perform TLS scanning.
        screenshots_only: Only capture screenshots.
    """
    from core.checkpoint import CheckpointManager, CheckpointData, make_output_dir, new_scan_id
    from core.input_parser import parse_targets
    from core.target_manager import TargetManager
    from core.scheduler import ScanConfig, ScanContext, run_scan
    from engine.findings import ScanResult
    from cli.progress import ScanProgressDisplay

    scan_id = resume_checkpoint.scan_id if resume_checkpoint else new_scan_id()

    # Create output directory
    if resume_checkpoint:
        scan_output_dir = output_dir
    else:
        scan_output_dir = make_output_dir(output_dir, scan_id, scan_title)

    console.print(f"[dim]Output directory:[/] {scan_output_dir}")

    # Parse targets
    console.print(f"[dim]Parsing {len(raw_targets)} target entries...[/]")
    parsed_targets = parse_targets(raw_targets)
    console.print(f"[dim]Resolved to {len(parsed_targets)} unique targets.[/]")

    if not parsed_targets:
        console.print("[red]No valid targets after parsing. Exiting.[/]")
        raise typer.Exit(1)

    # Skip completed targets if resuming
    skip_completed = []
    if resume_checkpoint:
        skip_completed = resume_checkpoint.completed

    manager = TargetManager(parsed_targets, skip_completed=skip_completed)
    cp_mgr = CheckpointManager(scan_output_dir)

    scan_result = ScanResult(
        scan_id=scan_id,
        title=scan_title,
        profile=profile,
        output_dir=scan_output_dir,
    )

    config = ScanConfig(
        scan_id=scan_id,
        title=scan_title,
        profile=profile,
        concurrency=min(concurrency, 50),
        timeout=timeout,
        output_dir=scan_output_dir,
        no_screenshots=no_screenshots,
        no_cve=no_cve,
        ports_only=ports_only,
        smb_only=smb_only,
        web_only=web_only,
        tls_only=tls_only,
        screenshots_only=screenshots_only,
    )

    display = ScanProgressDisplay(scan_title, manager.total)

    def on_finding(finding) -> None:
        display.add_finding(finding)

    def on_progress(mgr) -> None:
        display.update(mgr)

    ctx = ScanContext(
        config=config,
        manager=manager,
        checkpoint_mgr=cp_mgr,
        scan_result=scan_result,
        finding_callback=on_finding,
        progress_callback=on_progress,
    )

    display.start()
    try:
        asyncio.run(run_scan(ctx))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted — checkpoint saved.[/]")
    finally:
        display.stop()

    display.print_final_summary(manager, scan_result.all_findings)

    # Generate reports
    console.print("\n[dim]Generating reports...[/]")
    _generate_reports(scan_result, "both")

    console.print(f"\n[bold green]✓ Scan complete.[/] Results saved to [cyan]{scan_output_dir}[/]")

    # Clean up checkpoint on successful completion
    if manager.is_done():
        cp_mgr.delete()


def _generate_reports(scan_result, format: str) -> None:
    """Generate HTML and/or PDF reports.

    Args:
        scan_result: Completed ScanResult.
        format: 'html', 'pdf', or 'both'.
    """
    if format in ("html", "both"):
        try:
            from reporting.html_report import generate_html_report
            html_path = generate_html_report(scan_result)
            console.print(f"[green]✓ HTML report:[/] {html_path}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]HTML report failed: {exc}[/]")

    if format in ("pdf", "both"):
        try:
            from reporting.pdf_report import generate_pdf_report
            pdf_path = generate_pdf_report(scan_result)
            console.print(f"[green]✓ PDF report:[/] {pdf_path}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]PDF report skipped: {exc}[/]")


if __name__ == "__main__":
    app()
