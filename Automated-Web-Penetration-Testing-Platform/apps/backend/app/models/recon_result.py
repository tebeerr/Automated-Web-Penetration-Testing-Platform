import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class ReconResult(Base):
    """Stored Nmap reconnaissance output for one scan."""

    __tablename__ = "recon_results"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_matches: Mapped[list[Any]] = mapped_column(JSON, default=list)
    services: Mapped[list[Any]] = mapped_column(JSON, default=list)
    vuln_scripts: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw_xml: Mapped[str | None] = mapped_column(Text)
    scan_duration: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan = relationship("Scan", back_populates="recon_results")
