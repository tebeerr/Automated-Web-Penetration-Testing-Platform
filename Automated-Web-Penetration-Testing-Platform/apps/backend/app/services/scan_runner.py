"""End-to-end scan execution: probes → vuln rows → PDF report.

Scheduled as a one-shot APScheduler job from the scans route.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import SessionLocal
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SeverityLevel, Vulnerability

# Make the in-repo packages importable without `pip install -e ./packages/*`
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
for sub in ("scan-engine", "report-gen"):
    candidate = _PROJECT_ROOT / "packages" / sub
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

log = logging.getLogger(__name__)


async def run_scan_job(scan_id: str) -> None:
    """Top-level job entry point. Runs the full pipeline for one scan row."""
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            log.error("Scan %s not found; abort.", scan_id)
            return

        try:
            await _execute(db, scan)
        except Exception as e:
            log.exception("Scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.end_time = datetime.now(timezone.utc)
            await db.commit()


async def _execute(db: AsyncSession, scan: Scan) -> None:
    from engine.orchestrator import ScanOrchestrator
    from engine.probes import ALL_PROBES

    async def progress(phase: str, percent: int, message: str) -> None:
        try:
            scan.status = ScanStatus(phase) if phase in ScanStatus.__members__.values() else scan.status
        except ValueError:
            pass
        if phase == "recon":
            scan.status = ScanStatus.RECON
        elif phase == "scanning":
            scan.status = ScanStatus.SCANNING
        scan.progress = percent
        scan.current_phase = message
        await db.commit()

    # Phase 1: validating → recon
    scan.status = ScanStatus.VALIDATING
    scan.progress = 2
    scan.current_phase = "Validating target"
    scan.start_time = datetime.now(timezone.utc)
    await db.commit()

    # Phase 2: probes
    orchestrator = ScanOrchestrator(
        probes=[cls() for cls in ALL_PROBES],
        user_agent=settings.SCAN_USER_AGENT,
        request_delay_ms=settings.SCAN_REQUEST_DELAY_MS,
    )
    orchestrator.on_progress(progress)
    findings = await orchestrator.run(scan.target_url)

    # Phase 3: persist findings as Vulnerability rows
    scan.status = ScanStatus.SCANNING
    scan.progress = 96
    scan.current_phase = f"Persisting {len(findings)} findings"
    await db.commit()

    for f in findings:
        vuln = Vulnerability(
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
        db.add(vuln)

    # Phase 4: optional PDF report (best-effort; missing weasyprint shouldn't fail the scan).
    scan.status = ScanStatus.GENERATING_REPORT
    scan.progress = 98
    scan.current_phase = "Generating report"
    await db.commit()

    pdf_path = await _maybe_render_report(scan, findings)
    if pdf_path:
        size_kb = max(1, os.path.getsize(pdf_path) // 1024)
        db.add(
            Report(
                scan_id=scan.id,
                report_type="full",
                file_path=pdf_path,
                file_size_kb=size_kb,
                ai_summary=None,
            )
        )

    # Done
    scan.status = ScanStatus.COMPLETED
    scan.progress = 100
    scan.current_phase = "Scan complete"
    scan.end_time = datetime.now(timezone.utc)
    await db.commit()


async def _maybe_render_report(scan: Scan, findings: list[Any]) -> str | None:
    try:
        from generator.pdf_builder import PDFReportBuilder
    except Exception as e:
        log.info("Report generator not available: %s", e)
        return None

    stats = _aggregate(findings)
    builder = PDFReportBuilder()
    try:
        return await builder.generate(
            scan=scan,
            findings=findings,
            summary="",
            stats=stats,
            output_dir=settings.REPORTS_DIR,
        )
    except Exception as e:
        log.warning("PDF generation failed: %s", e)
        return None


def _aggregate(findings: list[Any]) -> dict[str, int]:
    out = {"total": len(findings), "real": 0, "false_positives": 0,
           "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if getattr(f, "is_false_positive", False):
            out["false_positives"] += 1
            continue
        out["real"] += 1
        sev = getattr(getattr(f, "severity", None), "value", "info")
        if sev in out:
            out[sev] += 1
    return out
