# ============================================================
# RECON-X | core/scheduler.py
# Description: Async orchestrator that runs all scan modules per
#              target in the correct order with concurrency control
# ============================================================

import asyncio
import logging
import signal
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine, List, Optional

from core.checkpoint import CheckpointData, CheckpointManager
from core.input_parser import Target
from core.target_manager import ManagedTarget, TargetManager, TargetState
from engine.findings import Finding, ScanResult, TargetResult

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    scan_id: str
    title: str
    profile: str = "normal"
    concurrency: int = 10
    timeout: int = 300
    output_dir: str = "./output"
    no_screenshots: bool = False
    no_cve: bool = False
    # Module-specific options
    ports_only: bool = False  # Only port scanning, no service modules
    smb_only: bool = False    # Only SMB scanning
    web_only: bool = False    # Only web scanning
    tls_only: bool = False    # Only TLS scanning
    screenshots_only: bool = False  # Only screenshots


@dataclass
class ScanContext:
    """Runtime context passed to worker coroutines."""
    config: ScanConfig
    manager: TargetManager
    checkpoint_mgr: CheckpointManager
    scan_result: ScanResult
    finding_callback: Optional[Callable[[Finding], None]] = None
    progress_callback: Optional[Callable[[TargetManager], None]] = None


async def _run_with_timeout(
    coro: Coroutine[Any, Any, Any],
    timeout: int,
    label: str,
) -> Any:
    """Run a coroutine with a timeout. Returns None on timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Timeout (%ds) reached for %s", timeout, label)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("Error in %s: %s", label, exc, exc_info=True)
        return None


async def _scan_target(ctx: ScanContext, mt: ManagedTarget) -> TargetResult:
    """Execute all scan modules for a single target in the correct order.

    Phase order:
      1. Discovery (ping + quick TCP)
      2. Nmap (parallel with phase 3 if alive)
      3. Service modules (SMB, RDP, VNC, Telnet, Web, TLS) - port-gated
      4. Screenshots (after web modules)
      5. CVE correlation (after versions known)

    Args:
        ctx: Scan context with config, manager, and callbacks.
        mt: The ManagedTarget to scan.

    Returns:
        TargetResult with all findings and metadata.
    """
    target = mt.target
    scan_start = datetime.utcnow()
    result = TargetResult(
        target=target,
        status="scanning",
        scan_start=scan_start,
        scan_end=scan_start,
    )

    label = target.display_name
    logger.info("Starting scan for %s", label)

    # ── Phase 1: Discovery ─────────────────────────────────────────────────
    try:
        from modules.nmap.nmap_runner import NmapRunner
        runner = NmapRunner(ctx.config.profile)

        # Quick port check to determine if host is alive
        discovery_result = await asyncio.get_event_loop().run_in_executor(
            None, runner.quick_discovery, target.ip or target.hostname or ""
        )
        if not discovery_result.get("alive", False):
            result.status = "unreachable"
            result.scan_end = datetime.utcnow()
            logger.info("Host %s is unreachable, skipping full scan", label)
            return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("Discovery failed for %s: %s", label, exc)
        # Continue anyway – may still respond to service probes

    # ── Phase 2: Nmap ─────────────────────────────────────────────────────
    open_ports = []
    nmap_xml = ""
    try:
        nmap_task = asyncio.get_event_loop().run_in_executor(
            None,
            runner.run_scan,
            target.ip or target.hostname or "",
        )
        nmap_raw = await _run_with_timeout(nmap_task, int(ctx.config.timeout * 0.6), f"nmap:{label}")
        if nmap_raw:
            from modules.nmap.nmap_parser import NmapParser
            parser = NmapParser()
            open_ports = parser.parse(nmap_raw.get("xml", ""))
            nmap_xml = nmap_raw.get("xml", "")
            result.open_ports = open_ports
            result.raw_nmap_xml = nmap_xml
            logger.info("%s: %d open ports found", label, len(open_ports))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Nmap failed for %s: %s", label, exc)

    # ── Phase 3: Service Modules ──────────────────────────────────────────
    port_numbers = {p.port_number for p in open_ports}
    service_tasks = []

    # Skip service modules if ports_only is enabled
    if ctx.config.ports_only:
        logger.info("%s: Ports-only scan - skipping service modules", label)
        run_all = False
    else:
        # Determine which modules to run
        run_all = not (ctx.config.smb_only or ctx.config.web_only or ctx.config.tls_only or ctx.config.screenshots_only)

        # SMB
        if (run_all or ctx.config.smb_only) and {445, 139} & port_numbers:
            from modules.smb.smb_scanner import SMBScanner
            smb = SMBScanner(target, open_ports)
            service_tasks.append(("smb", asyncio.get_event_loop().run_in_executor(None, smb.run)))

        # TLS (HTTPS or any 443 variant)
        web_tls_ports = port_numbers & {443, 8443, 4443, 8080, 80}
        if (run_all or ctx.config.tls_only) and web_tls_ports:
            from modules.tls.cert_analyzer import CertAnalyzer
            from modules.tls.cipher_checker import CipherChecker
            from modules.tls.hsts_checker import HSTSChecker
            tls_host = target.hostname or target.ip or ""
            for port in web_tls_ports:
                cert_analyzer = CertAnalyzer(tls_host, port)
                service_tasks.append((f"tls_cert:{port}", cert_analyzer.analyze()))
                if port in {443, 8443}:
                    cipher = CipherChecker(tls_host, port)
                    service_tasks.append((f"tls_cipher:{port}", cipher.check()))
            hsts = HSTSChecker(tls_host)
            service_tasks.append(("hsts", hsts.check()))

        # Web headers and security checks
        if (run_all or ctx.config.web_only) and (web_tls_ports or {80, 8080, 8443} & port_numbers):
            from modules.web.header_scanner import HeaderScanner
            from modules.web.clickjack import ClickjackChecker
            web_host = target.hostname or target.ip or ""
            for scheme in (target.schemes or ["http", "https"]):
                hs = HeaderScanner(scheme, web_host)
                service_tasks.append((f"headers:{scheme}", hs.scan()))
                cj = ClickjackChecker(scheme, web_host)
                service_tasks.append((f"clickjack:{scheme}", cj.check()))

        # Banner grabbing (only if not screenshots-only)
        if (run_all or not ctx.config.screenshots_only) and open_ports:
            from modules.web.banner_grabber import BannerGrabber
            host_str = target.ip or target.hostname or ""
            bg = BannerGrabber(host_str, [p.port_number for p in open_ports])
            service_tasks.append(("banners", bg.grab_all()))

        # RDP (only if not screenshots-only)
        if (run_all or not ctx.config.screenshots_only) and 3389 in port_numbers:
            from modules.rdp_vnc.rdp_scanner import RDPScanner
            rdp = RDPScanner(target.ip or target.hostname or "")
            service_tasks.append(("rdp", asyncio.get_event_loop().run_in_executor(None, rdp.scan)))

        # VNC (only if not screenshots-only)
        vnc_ports = port_numbers & set(range(5900, 5911))
        if (run_all or not ctx.config.screenshots_only) and vnc_ports:
            from modules.rdp_vnc.vnc_telnet import VNCScanner
            for vp in vnc_ports:
                vnc = VNCScanner(target.ip or target.hostname or "", vp)
                service_tasks.append((f"vnc:{vp}", asyncio.get_event_loop().run_in_executor(None, vnc.scan)))

        # Telnet (only if not screenshots-only)
        if (run_all or not ctx.config.screenshots_only) and 23 in port_numbers:
            from modules.rdp_vnc.vnc_telnet import TelnetScanner
            tel = TelnetScanner(target.ip or target.hostname or "")
            service_tasks.append(("telnet", asyncio.get_event_loop().run_in_executor(None, tel.scan)))

    # Run all service tasks concurrently
    for task_label, coro_or_future in service_tasks:
        try:
            task_result = await _run_with_timeout(
                coro_or_future if asyncio.iscoroutine(coro_or_future) else asyncio.wrap_future(coro_or_future),
                int(ctx.config.timeout * 0.3),
                f"{task_label}:{label}",
            )
            if task_result is None:
                continue
            if hasattr(task_result, "findings"):
                result.findings.extend(task_result.findings)
            if hasattr(task_result, "cert_result"):
                result.cert_result = task_result.cert_result
            if hasattr(task_result, "banners"):
                result.banners.extend(task_result.banners)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Service task %s failed for %s: %s", task_label, label, exc)

    # ── Phase 4: Screenshots ──────────────────────────────────────────────
    if not ctx.config.no_screenshots and (run_all or ctx.config.screenshots_only) and (target.schemes or web_tls_ports):
        try:
            from modules.web.screenshot import ScreenshotCapture
            host_str = target.hostname or target.ip or ""
            sc = ScreenshotCapture(host_str, target.schemes or ["http", "https"], ctx.config.output_dir)
            screenshot_results = await _run_with_timeout(sc.capture_all(), 60, f"screenshots:{label}")
            if screenshot_results:
                result.screenshots.extend(screenshot_results)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Screenshots failed for %s: %s", label, exc)

    # ── Phase 5: CVE Lookup ───────────────────────────────────────────────
    if not ctx.config.no_cve and (run_all or ctx.config.screenshots_only) and open_ports:
        try:
            from modules.cve.cve_lookup import CVELookup
            product_versions = [
                (p.product or p.service_name, p.service_version)
                for p in open_ports
                if p.service_name or p.product
            ]
            if product_versions:
                cve_lookup = CVELookup(ctx.config.output_dir)
                cve_findings = await asyncio.get_event_loop().run_in_executor(
                    None, cve_lookup.lookup_all, product_versions, str(target.ip or target.hostname)
                )
                result.findings.extend(cve_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CVE lookup failed for %s: %s", label, exc)

    result.status = "completed"
    result.scan_end = datetime.utcnow()

    # Fire finding callbacks
    if ctx.finding_callback:
        for finding in result.findings:
            try:
                ctx.finding_callback(finding)
            except Exception:  # noqa: BLE001
                pass

    logger.info(
        "%s: scan complete — %d findings in %.1fs",
        label,
        len(result.findings),
        (result.scan_end - result.scan_start).total_seconds(),
    )
    return result


async def _worker(ctx: ScanContext, worker_id: str) -> None:
    """Worker coroutine: pulls targets from manager until exhausted.

    Args:
        ctx: Shared scan context.
        worker_id: Identifier for logging.
    """
    while True:
        mt = ctx.manager.get_next()
        if mt is None:
            break

        target = mt.target
        label = target.display_name

        try:
            result = await asyncio.wait_for(
                _scan_target(ctx, mt),
                timeout=ctx.config.timeout,
            )
            ctx.scan_result.target_results.append(result)
            ctx.manager.mark_completed(target, worker_id)
        except asyncio.TimeoutError:
            logger.warning("Worker %s: target %s timed out", worker_id, label)
            ctx.manager.mark_timeout(target, worker_id)
            timeout_result = TargetResult(
                target=target,
                status="timeout",
                scan_start=mt.started_at or datetime.utcnow(),
                scan_end=datetime.utcnow(),
            )
            ctx.scan_result.target_results.append(timeout_result)
        except Exception as exc:  # noqa: BLE001
            logger.error("Worker %s: target %s failed: %s", worker_id, label, exc, exc_info=True)
            ctx.manager.mark_failed(target, str(exc), worker_id)
            failed_result = TargetResult(
                target=target,
                status="failed",
                scan_start=mt.started_at or datetime.utcnow(),
                scan_end=datetime.utcnow(),
            )
            ctx.scan_result.target_results.append(failed_result)

        # Save checkpoint after every target
        snap = ctx.manager.snapshot()
        cp_data = CheckpointData(
            scan_id=ctx.config.scan_id,
            title=ctx.config.title,
            started_at=ctx.scan_result.started_at.isoformat(),
            total_targets=ctx.manager.total,
            completed=snap.get("completed", []),
            failed=snap.get("failed", []),
            timeout=snap.get("timeout", []),
            pending=snap.get("pending", []),
            in_progress=snap.get("in_progress", []),
            skipped=snap.get("skipped", []),
            findings=[],  # findings serialized separately
            scan_profile=ctx.config.profile,
            output_dir=ctx.config.output_dir,
        )
        ctx.checkpoint_mgr.save(cp_data)

        if ctx.progress_callback:
            try:
                ctx.progress_callback(ctx.manager)
            except Exception:  # noqa: BLE001
                pass


async def run_scan(ctx: ScanContext) -> ScanResult:
    """Main async entry point that runs all workers.

    Args:
        ctx: Fully populated ScanContext.

    Returns:
        Completed ScanResult with all target results and findings.
    """
    ctx.scan_result.started_at = datetime.utcnow()
    concurrency = min(ctx.config.concurrency, 50)

    shutdown_event = asyncio.Event()

    def _handle_sigint(*_: Any) -> None:
        logger.warning("Ctrl+C received — saving checkpoint and shutting down...")
        shutdown_event.set()

    # Register SIGINT handler for graceful shutdown
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, _handle_sigint)
    except (NotImplementedError, OSError):
        pass  # Windows doesn't support add_signal_handler

    worker_tasks = [
        asyncio.create_task(_worker(ctx, f"worker-{i}"), name=f"worker-{i}")
        for i in range(concurrency)
    ]

    # Wait for either all workers to finish or shutdown signal
    done, pending = await asyncio.wait(
        worker_tasks,
        return_when=asyncio.ALL_COMPLETED,
    )

    # Cancel remaining on shutdown
    if shutdown_event.is_set():
        for task in pending:
            task.cancel()
        logger.info("Graceful shutdown: %d workers cancelled", len(pending))

    ctx.scan_result.finished_at = datetime.utcnow()

    # Deduplicate findings across all results
    from engine.deduplicator import deduplicate_findings
    all_findings: List[Finding] = []
    for tr in ctx.scan_result.target_results:
        all_findings.extend(tr.findings)
    ctx.scan_result.all_findings = deduplicate_findings(all_findings)

    logger.info(
        "Scan complete: %d targets, %d findings in %.1fs",
        len(ctx.scan_result.target_results),
        len(ctx.scan_result.all_findings),
        (ctx.scan_result.finished_at - ctx.scan_result.started_at).total_seconds(),
    )

    return ctx.scan_result
