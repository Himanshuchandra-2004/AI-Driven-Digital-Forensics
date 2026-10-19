"""ChainOfCustody model — tamper-evident audit trail for evidence."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("evidence.id"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # collected, uploaded, processed, analyzed, viewed, verified, exported, report_generated
    description: Mapped[str] = mapped_column(Text, nullable=True)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )

    # Relationships
    evidence = relationship("Evidence", back_populates="chain_of_custody")
    user = relationship("User", back_populates="custody_actions")
