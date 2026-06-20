import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Numeric, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class RLFeedback(Base):
    __tablename__ = "rl_feedback"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    agent_name: Mapped[str | None] = mapped_column(String(100))
    reward: Mapped[Decimal | None] = mapped_column(Numeric(4, 3))
    tech_stack: Mapped[str | None] = mapped_column(String(100))
    feedback_type: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
