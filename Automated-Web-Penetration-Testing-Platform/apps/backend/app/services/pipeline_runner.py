"""Pipeline Runner — orchestrates Recon → Web → Exploit → Post-Exploit.

Used instead of scan_runner.run_scan_job when scan_profile is 'recon_web' or
'full_pipeline'. Scheduled as a one-shot APScheduler job from the scans route.

Phase flow by scan_profile:
    web_only      → handled by scan_runner.run_scan_job (not here)
    recon_web     → nmap recon + web probes
    full_pipeline → nmap recon + web probes + exploit + post-exploit
"""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from app.config import settings
from app.database import SessionLocal
from app.models.recon_result import ReconResult as ReconResultModel
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SeverityLevel, Vulnerability

# Make the in-repo packages importable without `pip install -e ./packages/*`.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
for _sub in ("scan-engine", "report-gen"):
    _candidate = _PROJECT_ROOT / "packages" / _sub
    if _candidate.exists() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

log = logging.getLogger(__name__)


async def run_pipeline_job(scan_id: str) -> None:
    """Top-level pipeline entry point. Runs the multi-phase pipeline for one scan."""
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            log.error("Scan %s not found; abort.", scan_id)
            return
        try:
            await _execute(db, scan)
        except Exception as e:
            log.exception("Pipeline scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)[:500]
            scan.end_time = datetime.now(timezone.utc)
            await db.commit()


async def _execute(db, scan: Scan) -> None:
    from engine.probes.base import ProbeContext

    profile = scan.scan_profile or "web_only"
    all_findings: list[Any] = []
    recon = None
    msf = None

    scan.start_time = datetime.now(timezone.utc)

    # Shared context — carries recon_result from nmap into the MSF probes.
    ctx = ProbeContext(target_url=scan.target_url, client=None)

    try:
        # ── Phase 1: Reconnaissance (nmap) ───────────────────────────
        if profile in ("recon_web", "full_pipeline"):
            scan.status = ScanStatus.RECON
            scan.progress = 5
            scan.current_phase = "Reconnaissance (nmap)"
            await db.commit()

            from engine.probes.nmap_recon import NmapReconProbe

            nmap_probe = NmapReconProbe(config={
                "nmap_scan_args": settings.NMAP_SCAN_ARGS,
                "nmap_vuln_args": settings.NMAP_VULN_ARGS,
                "nmap_os_detection": settings.NMAP_OS_DETECTION,
                "nmap_timeout_seconds": settings.NMAP_TIMEOUT_SECONDS,
            })
            recon_findings = await nmap_probe.run(ctx)
            all_findings.extend(recon_findings)
            recon = getattr(ctx, "recon_result", None)
            if recon is not None:
                _persist_recon(db, scan, recon)
            scan.progress = 25
            await db.commit()
            log.info("[PIPELINE] Recon complete: %d findings", len(recon_findings))

        # ── Phase 2: Web probes ──────────────────────────────────────
        scan.status = ScanStatus.SCANNING
        scan.progress = 30
        scan.current_phase = "Web probes"
        await db.commit()

        from engine.orchestrator import ScanOrchestrator
        from engine.probes import ALL_PROBES

        async def progress(phase: str, percent: int, message: str) -> None:
            # Map orchestrator's 0-100 onto the 30-60 web window.
            scan.progress = 30 + int(percent * 0.3)
            scan.current_phase = message
            await db.commit()

        orchestrator = ScanOrchestrator(
            probes=[cls() for cls in ALL_PROBES],
            user_agent=settings.SCAN_USER_AGENT,
            request_delay_ms=settings.SCAN_REQUEST_DELAY_MS,
        )
        orchestrator.on_progress(progress)
        web_findings = await orchestrator.run(scan.target_url)
        all_findings.extend(web_findings)
        scan.progress = 60
        await db.commit()
        log.info("[PIPELINE] Web probes complete: %d findings", len(web_findings))

        # ── Phase 3: Exploitation (Metasploit) ───────────────────────
        if profile == "full_pipeline" and settings.MSF_EXPLOIT_ENABLED:
            scan.status = ScanStatus.EXPLOITING
            scan.progress = 65
            scan.current_phase = "Exploitation (Metasploit)"
            await db.commit()

            from app.services.msf_client import MetasploitClient
            from engine.probes.msf_exploit import MetasploitExploitProbe

            msf_config = {
                "msf_rpc_host": settings.MSF_RPC_HOST,
                "msf_rpc_port": settings.MSF_RPC_PORT,
                "msf_rpc_password": settings.MSF_RPC_PASSWORD,
                "msf_rpc_ssl": settings.MSF_RPC_SSL,
                "msf_workspace": settings.MSF_WORKSPACE,
                "msf_allowed_module_prefixes": settings.MSF_ALLOWED_MODULE_PREFIXES,
                "msf_blocked_modules": settings.MSF_BLOCKED_MODULES,
                "msf_exploit_enabled": settings.MSF_EXPLOIT_ENABLED,
                "msf_max_exploit_attempts": settings.MSF_MAX_EXPLOIT_ATTEMPTS,
            }
            msf = MetasploitClient(msf_config)
            exploit_probe = MetasploitExploitProbe(msf, config=msf_config)
            exploit_findings = await exploit_probe.run(ctx)
            all_findings.extend(exploit_findings)
            scan.progress = 80
            await db.commit()
            log.info("[PIPELINE] Exploitation complete: %d findings", len(exploit_findings))

            # ── Phase 4: Post-Exploitation ───────────────────────────
            if settings.POST_EXPLOIT_ENABLED:
                scan.status = ScanStatus.POST_EXPLOIT
                scan.progress = 85
                scan.current_phase = "Post-exploitation"
                await db.commit()

                from engine.probes.msf_postexploit import MetasploitPostExploitProbe

                post_probe = MetasploitPostExploitProbe(msf, config={
                    "post_exploit_enabled": settings.POST_EXPLOIT_ENABLED,
                    "post_exploit_actions": settings.POST_EXPLOIT_ACTIONS,
                })
                post_findings = await post_probe.run(ctx)
                all_findings.extend(post_findings)
                scan.progress = 90
                await db.commit()
                log.info(
                    "[PIPELINE] Post-exploitation complete: %d findings",
                    len(post_findings),
                )

        # ── Phase 5: Persist findings + report ───────────────────────
        scan.status = ScanStatus.GENERATING_REPORT
        scan.progress = 92
        scan.current_phase = "Persisting findings"
        await db.commit()

        for f in all_findings:
            db.add(_finding_to_vuln(scan, f))
        await db.commit()

        scan.current_phase = "Generating report"
        scan.progress = 96
        await db.commit()

        pdf_path = await _maybe_render_report(scan, all_findings)
        if pdf_path:
            size_kb = max(1, os.path.getsize(pdf_path) // 1024)
            db.add(Report(
                scan_id=scan.id,
                report_type="full",
                file_path=pdf_path,
                file_size_kb=size_kb,
                ai_summary=None,
            ))

        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.current_phase = "Scan complete"
        scan.end_time = datetime.now(timezone.utc)
        await db.commit()
        log.info("[PIPELINE] Scan %s completed (%d findings)", scan.id, len(all_findings))

    finally:
        if msf is not None:
            try:
                await msf.cleanup_sessions()
                await msf.disconnect()
            except Exception as e:
                log.warning("[PIPELINE] MSF cleanup failed: %s", e)


def _persist_recon(db, scan: Scan, recon) -> None:
    """Store the Nmap ReconResult dataclass as a recon_results row."""
    db.add(ReconResultModel(
        scan_id=scan.id,
        target_ip=recon.target_ip,
        hostname=recon.hostname,
        os_matches=recon.os_matches,
        services=[dataclasses.asdict(s) for s in recon.services],
        vuln_scripts=recon.vuln_scripts,
        raw_xml=recon.raw_xml or None,
        scan_duration=recon.scan_duration,
    ))


def _finding_to_vuln(scan: Scan, f: Any) -> Vulnerability:
    return Vulnerability(
        scan_id=scan.id,
        owasp_category=f.owasp_category,
        owasp_name=f.owasp_name,
        name=f.name,
        description=f.description,
        severity=SeverityLevel(f.severity.value),
        cvss_score=Decimal(str(f.cvss_score)) if f.cvss_score else None,
        cwe_id=f.cwe_id or None,
        evidence=f.evidence or None,
        payload=f.payload or None,
        url_affected=f.url_affected or None,
        parameter=f.parameter or None,
        remediation=f.remediation or None,
        ai_confidence=Decimal(str(f.ai_confidence)),
        ai_narrative=f.ai_narrative or None,
        source_scanner=f.source_scanner or None,
        is_false_positive=f.is_false_positive,
    )


async def _maybe_render_report(scan: Scan, findings: list[Any]) -> str | None:
    # Reuse the web-only report helper for consistent PDF output.
    from app.services.scan_runner import _maybe_render_report as _render
    return await _render(scan, findings)
