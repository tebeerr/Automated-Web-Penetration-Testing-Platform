import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    target_url: HttpUrl
    scan_profile: str = Field(default="owasp_top10", max_length=50)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID | None
    target_url: str
    target_id: uuid.UUID | None
    status: ScanStatus
    scan_profile: str
    progress: int
    current_phase: str | None
    start_time: datetime | None
    end_time: datetime | None
    error_message: str | None
    scan_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ScanProgressUpdate(BaseModel):
    """WebSocket payload published from worker to frontend."""

    scan_id: uuid.UUID
    status: ScanStatus
    progress: int
    current_phase: str | None = None
    message: str | None = None
