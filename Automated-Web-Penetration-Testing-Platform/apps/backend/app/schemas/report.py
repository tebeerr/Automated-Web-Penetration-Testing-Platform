import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    report_type: str
    file_path: str | None
    file_size_kb: int | None
    generated_at: datetime
    ai_summary: str | None
