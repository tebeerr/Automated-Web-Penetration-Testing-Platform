import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReconResultResponse(BaseModel):
    """Nmap reconnaissance results returned for a scan."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    target_ip: str
    hostname: str | None
    os_matches: list[Any] = Field(default_factory=list)
    services: list[Any] = Field(default_factory=list)
    vuln_scripts: list[Any] = Field(default_factory=list)
    scan_duration: float = 0.0
    created_at: datetime
