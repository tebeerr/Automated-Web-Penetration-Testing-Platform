import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    POST_EXPLOIT = "post_exploit"
    AI_ANALYZING = "ai_analyzing"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("verified_targets.id")
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.PENDING, index=True
    )
    scan_profile: Mapped[str] = mapped_column(String(50), default="owasp_top10")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_phase: Mapped[str | None] = mapped_column(String(100))
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    job_id: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(String)
    scan_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    recon_results = relationship(
        "ReconResult", back_populates="scan", cascade="all, delete-orphan"
    )
