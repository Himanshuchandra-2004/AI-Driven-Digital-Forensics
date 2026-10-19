"""Case model — forensic investigation cases."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True, default="")
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="open", index=True
    )  # open, analyzing, completed, archived
    severity: Mapped[str] = mapped_column(
        String(20), nullable=True, default=None
    )  # low, medium, high, critical
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_count: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user = relationship("User", back_populates="cases", lazy="selectin")
    analysis_runs = relationship("AnalysisRun", back_populates="case", lazy="selectin")
    evidence = relationship("Evidence", back_populates="case", lazy="selectin")
    incidents = relationship("Incident", back_populates="case", lazy="selectin")
    reports = relationship("Report", back_populates="case", lazy="selectin")
