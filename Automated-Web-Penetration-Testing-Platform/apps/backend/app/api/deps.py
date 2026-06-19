import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.services.security import decode_access_token

__all__ = ["get_db", "get_current_user", "get_optional_user", "AsyncDB"]

AsyncDB = AsyncGenerator[AsyncSession, None]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing authentication.")
    try:
        payload = decode_access_token(token)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token missing subject.")

    user = await db.get(User, uuid.UUID(user_id))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found.")
    return user


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    if not token:
        return None
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None
