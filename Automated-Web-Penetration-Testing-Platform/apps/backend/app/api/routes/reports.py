import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.report import Report
from app.models.scan import Scan
from app.models.user import User
from app.schemas.report import ReportResponse

router = APIRouter()


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = await db.execute(
        select(Report).join(Scan, Scan.id == Report.scan_id).where(Scan.user_id == user.id)
    )
    return [ReportResponse.model_validate(r) for r in rows.scalars().all()]


@router.get("/{report_id}")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = await db.get(Report, report_id)
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found.")

    scan = await db.get(Scan, report.scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not your report.")

    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report file missing on disk.")

    return FileResponse(
        report.file_path,
        media_type="application/pdf",
        filename=f"sentinel_report_{scan.id}.pdf",
    )
