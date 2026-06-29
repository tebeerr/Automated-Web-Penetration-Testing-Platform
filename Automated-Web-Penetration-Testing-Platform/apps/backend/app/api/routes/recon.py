from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.recon_result import ReconResult
from app.models.scan import Scan
from app.models.user import User
from app.schemas.recon import ReconResultResponse

router = APIRouter()


@router.get("/{scan_id}/recon", response_model=ReconResultResponse)
async def get_recon_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return Nmap reconnaissance results for a scan."""
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    row = await db.execute(
        select(ReconResult)
        .where(ReconResult.scan_id == scan.id)
        .order_by(ReconResult.created_at.desc())
    )
    recon = row.scalars().first()
    if not recon:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "No recon results for this scan."
        )
    return ReconResultResponse.model_validate(recon)
