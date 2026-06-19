"""Main scan pipeline: scan engine → AI analysis → report generation.

Implementation is a wired skeleton: it persists status changes and publishes
WebSocket progress frames. Replace the simulated phases with real ScanOrchestrator
+ AIOrchestrator + PDFReportBuilder calls as those packages come online.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.models.scan import Scan, ScanStatus
from workers.celery_app import celery_app
from workers.publisher import publish_scan_progress

log = logging.getLogger(__name__)


def _session_factory():
    engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    return async_sessionmaker(engine, expire_on_commit=False), engine


@celery_app.task(bind=True, name="scan.run", max_retries=2, soft_time_limit=1800)
def run_pentest_scan(self, scan_id: str) -> str:
    """Celery entry point. Schedules the async pipeline."""
    asyncio.run(_run_scan_async(scan_id))
    return scan_id


async def _run_scan_async(scan_id: str) -> None:
    Session, engine = _session_factory()
    try:
        async with Session() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                log.error("Scan %s not found in DB; abort.", scan_id)
                return

            try:
                await _set_status(db, scan, ScanStatus.VALIDATING, 5, "Validating target")
                await _set_status(db, scan, ScanStatus.RECON, 15, "Reconnaissance")
                await asyncio.sleep(0)  # placeholder for real recon

                await _set_status(db, scan, ScanStatus.SCANNING, 35, "Running scanners")
                # TODO: ScanOrchestrator(...).run(scan.target_url)

                await _set_status(
                    db, scan, ScanStatus.AI_ANALYZING, 70, "AI post-processing findings"
                )
                # TODO: AIOrchestrator(llm).analyze(findings, scan.target_url)

                await _set_status(
                    db, scan, ScanStatus.GENERATING_REPORT, 90, "Generating PDF report"
                )
                # TODO: PDFReportBuilder().generate(...)

                scan.status = ScanStatus.COMPLETED
                scan.progress = 100
                scan.current_phase = "Scan complete"
                scan.end_time = datetime.now(timezone.utc)
                await db.commit()
                publish_scan_progress(
                    scan_id,
                    {
                        "scan_id": scan_id,
                        "status": ScanStatus.COMPLETED.value,
                        "progress": 100,
                        "current_phase": "Scan complete",
                    },
                )

            except Exception as e:
                log.exception("Scan %s failed", scan_id)
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.end_time = datetime.now(timezone.utc)
                await db.commit()
                publish_scan_progress(
                    scan_id,
                    {
                        "scan_id": scan_id,
                        "status": ScanStatus.FAILED.value,
                        "progress": scan.progress,
                        "current_phase": "Failed",
                        "message": str(e),
                    },
                )
                raise
    finally:
        await engine.dispose()


async def _set_status(db, scan: Scan, status: ScanStatus, progress: int, phase: str) -> None:
    scan.status = status
    scan.progress = progress
    scan.current_phase = phase
    if scan.start_time is None:
        scan.start_time = datetime.now(timezone.utc)
    await db.commit()
    publish_scan_progress(
        str(scan.id),
        {
            "scan_id": str(scan.id),
            "status": status.value,
            "progress": progress,
            "current_phase": phase,
        },
    )
