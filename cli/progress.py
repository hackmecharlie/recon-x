# ============================================================
# RECON-X | cli/progress.py
# Description: Rich live progress display with target bars,
#              worker status, and scrolling findings ticker
# ============================================================

import time
from collections import deque
from datetime import datetime
from threading import Lock
from typing import Callable, Deque, List, Optional

from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from core.target_manager import TargetManager
from engine.findings import Finding

_SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "bold orange1",
    "Medium": "bold yellow",
    "Low": "bold green",
    "Informational": "dim white",
}

_MAX_TICKER_LINES = 5


class ScanProgressDisplay:
    """Live Rich display for scan progress.

    Shows:
    - RECON-X header with elapsed time
    - Overall progress bar
    - Active worker spinners
    - Rolling findings ticker (last 5 findings)
    """

    def __init__(self, title: str, total_targets: int) -> None:
        """Initialize the progress display.

        Args:
            title: Scan title shown in header.
            total_targets: Total number of targets to scan.
        """
        self.title = title
        self.total_targets = total_targets
        self.start_time = datetime.utcnow()
        self._lock = Lock()
        self._findings_ticker: Deque[Finding] = deque(maxlen=_MAX_TICKER_LINES)
        self._active_workers: List[str] = []
        self._current_module: str = ""
        self._console = Console()
        self._live: Optional[Live] = None

        # Main progress bar
        self._overall_progress = Progress(
            TextColumn("[dim]Overall[/]"),
            BarColumn(bar_width=40, style="blue", complete_style="cyan"),
            TextColumn("[cyan]{task.completed}[/]/[dim]{task.total}[/] targets"),
            TextColumn("[dim]·[/]"),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._overall_task: Optional[TaskID] = None

        # Module progress
        self._module_progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[dim]{task.description}[/]"),
            console=self._console,
        )

    def start(self) -> None:
        """Start the live display context."""
        self._overall_task = self._overall_progress.add_task(
            "scan", total=self.total_targets
        )
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="progress", size=6),
            Layout(name="ticker", size=8),
        )
        self._live = Live(
            self._build_renderable(),
            refresh_per_second=4,
            console=self._console,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()

    def update(self, manager: TargetManager) -> None:
        """Update the progress display from TargetManager state.

        Args:
            manager: Current TargetManager with state snapshot.
        """
        if self._overall_task is not None:
            completed = manager.completed_count + manager.failed_count
            self._overall_progress.update(
                self._overall_task, completed=completed
            )
        if self._live:
            self._live.update(self._build_renderable())

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the live ticker.

        Args:
            finding: New Finding to display.
        """
        with self._lock:
            self._findings_ticker.append(finding)
        if self._live:
            self._live.update(self._build_renderable())

    def set_active_workers(self, workers: List[str]) -> None:
        """Update active worker list.

        Args:
            workers: List of currently-active target names.
        """
        with self._lock:
            self._active_workers = workers[:]

    def _elapsed_str(self) -> str:
        """Return elapsed time as HH:MM:SS."""
        elapsed = int((datetime.utcnow() - self.start_time).total_seconds())
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _build_renderable(self) -> Panel:
        """Build the complete Rich renderable for the live display.

        Returns:
            Rich Panel containing the full progress UI.
        """
        parts = []

        # Header line
        header = Text()
        header.append("◈ RECON-X", style="bold cyan")
        header.append("  ·  ", style="dim")
        header.append(self.title, style="bold white")
        header.append("  ·  ", style="dim")
        header.append(f"⏱ {self._elapsed_str()}", style="dim cyan")
        parts.append(header)
        parts.append(Text(""))

        # Overall progress
        parts.append(self._overall_progress)

        # Active workers
        with self._lock:
            workers = list(self._active_workers)
        if workers:
            parts.append(Text(""))
            worker_text = Text()
            worker_text.append("  Active: ", style="dim")
            for w in workers[:8]:
                worker_text.append(f"⟳ {w}  ", style="blue")
            parts.append(worker_text)

        # Findings ticker
        with self._lock:
            recent = list(self._findings_ticker)
        if recent:
            parts.append(Text(""))
            ticker_table = Table.grid(padding=(0, 1))
            ticker_table.add_column(width=14)
            ticker_table.add_column()
            for f in reversed(recent):
                style = _SEVERITY_STYLES.get(f.severity, "white")
                label = Text(f"[{f.severity[:4].upper()}]", style=style)
                detail = Text(f"{f.target}:{f.port or ''}  {f.title[:60]}", style="dim white")
                ticker_table.add_row(label, detail)
            parts.append(ticker_table)

        return Panel(
            Group(*parts),
            border_style="blue",
            title="[bold blue]RECON-X[/]",
            subtitle=f"[dim]{self._elapsed_str()} elapsed[/]",
        )

    def print_final_summary(self, manager: TargetManager, findings: List[Finding]) -> None:
        """Print final scan summary table.

        Args:
            manager: Completed TargetManager.
            findings: All collected findings.
        """
        from collections import Counter
        severity_counts = Counter(f.severity for f in findings)

        table = Table(
            title="[bold cyan]◈ RECON-X Scan Complete[/]",
            show_header=True,
            header_style="bold dim",
            border_style="blue",
        )
        table.add_column("Metric", style="dim", width=24)
        table.add_column("Value", style="bold")

        table.add_row("Total Targets", str(manager.total))
        table.add_row("Completed", f"[green]{manager.completed_count}[/]")
        table.add_row("Failed / Timeout", f"[red]{manager.failed_count}[/]")
        table.add_row("Total Findings", f"[bold]{len(findings)}[/]")
        table.add_row("Critical", f"[bold red]{severity_counts.get('Critical', 0)}[/]")
        table.add_row("High", f"[bold orange1]{severity_counts.get('High', 0)}[/]")
        table.add_row("Medium", f"[bold yellow]{severity_counts.get('Medium', 0)}[/]")
        table.add_row("Low", f"[bold green]{severity_counts.get('Low', 0)}[/]")
        table.add_row("Informational", f"[dim]{severity_counts.get('Informational', 0)}[/]")

        self._console.print()
        self._console.print(table)
