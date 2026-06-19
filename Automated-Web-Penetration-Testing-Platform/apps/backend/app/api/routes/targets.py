from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.models.verified_target import VerifiedTarget
from app.schemas.target import (
    VerificationConfirm,
    VerificationStart,
    VerificationStartResponse,
    VerifiedTargetResponse,
)
from app.services.target_verification import (
    generate_token,
    verify_dns,
    verify_file,
    verify_meta_tag,
)

router = APIRouter()

_VERIFIER = {
    "dns_txt": verify_dns,
    "meta_tag": verify_meta_tag,
    "file_upload": verify_file,
}

_INSTRUCTIONS = {
    "dns_txt": "Add a TXT record on {domain} with the value {token}, then call /confirm.",
    "meta_tag": (
        'Add <meta name="sentinel-verification" content="{token}"> to the HTML '
        "of https://{domain}/, then call /confirm."
    ),
    "file_upload": (
        "Serve a UTF-8 file at https://{domain}/.well-known/sentinel-verification.txt "
        "whose only content is {token}, then call /confirm."
    ),
}


@router.post("/verification/start", response_model=VerificationStartResponse)
async def start_verification(
    payload: VerificationStart,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    token = generate_token()
    target = VerifiedTarget(
        user_id=user.id,
        domain=payload.domain.lower(),
        verification=payload.method,
        verification_token=token,
        verified_at=datetime.now(timezone.utc),
        expires_at=None,
    )
    db.add(target)
    await db.commit()

    return VerificationStartResponse(
        domain=payload.domain,
        method=payload.method,
        token=token,
        instructions=_INSTRUCTIONS[payload.method].format(domain=payload.domain, token=token),
    )


@router.post("/verification/confirm", response_model=VerifiedTargetResponse)
async def confirm_verification(
    payload: VerificationConfirm,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(VerifiedTarget).where(
            VerifiedTarget.user_id == user.id,
            VerifiedTarget.domain == payload.domain.lower(),
            VerifiedTarget.verification == payload.method,
        )
    )
    target = result.scalar_one_or_none()
    if not target or not target.verification_token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No pending verification for this domain.")

    verifier = _VERIFIER[payload.method]
    if not await verifier(payload.domain, target.verification_token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Verification check failed.")

    target.verified_at = datetime.now(timezone.utc)
    target.expires_at = target.verified_at + timedelta(days=90)
    await db.commit()
    await db.refresh(target)
    return VerifiedTargetResponse.model_validate(target)


@router.get("/", response_model=list[VerifiedTargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = await db.execute(select(VerifiedTarget).where(VerifiedTarget.user_id == user.id))
    return [VerifiedTargetResponse.model_validate(t) for t in rows.scalars().all()]
