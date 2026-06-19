import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class VerificationStart(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    method: Literal["dns_txt", "meta_tag", "file_upload"]


class VerificationStartResponse(BaseModel):
    domain: str
    method: str
    token: str
    instructions: str


class VerificationConfirm(BaseModel):
    domain: str
    method: Literal["dns_txt", "meta_tag", "file_upload"]


class VerifiedTargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    domain: str
    verification: str
    verified_at: datetime
    expires_at: datetime | None
