from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.verified_target import VerifiedTarget
from app.models.vulnerability import Vulnerability
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.services.url_validator import URLValidationError, validate_target_url

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        validated_url, hostname = validate_target_url(str(payload.target_url))
    except URLValidationError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e

    # Domain ownership gate.
    target_row = await db.execute(
        select(VerifiedTarget).where(
            VerifiedTarget.user_id == user.id,
            VerifiedTarget.domain == hostname,
        )
    )
    target = target_row.scalar_one_or_none()
    if not target:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Domain '{hostname}' is not verified. Run domain verification first.",
        )

    scan = Scan(
        user_id=user.id,
        target_url=validated_url,
        target_id=target.id,
        scan_profile=payload.scan_profile,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue Celery task. Local import keeps backend importable when worker module absent.
    try:
        from workers.tasks.scan_task import run_pentest_scan

        task = run_pentest_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        await db.commit()
        await db.refresh(scan)
    except Exception:
        # Worker not reachable from API in dev; surface task id as None and proceed.
        pass

    return ScanResponse.model_validate(scan)


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = await db.execute(
        select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc())
    )
    return [ScanResponse.model_validate(s) for s in rows.scalars().all()]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    rows = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan.id)
    )
    return [VulnerabilityResponse.model_validate(v) for v in rows.scalars().all()]


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan already terminal.")

    scan.status = ScanStatus.CANCELLED
    await db.commit()
    await db.refresh(scan)

    if scan.celery_task_id:
        try:
            from workers.celery_app import celery_app

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception:
            pass

    # Use parse_url so caller can also use this internally.
    _ = urlparse(scan.target_url)
    return ScanResponse.model_validate(scan)
