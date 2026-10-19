"""Anomaly model — Isolation Forest detection results."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    network_event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("network_events.id"), nullable=False, unique=True
    )
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("analysis_runs.id"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id"), nullable=False, index=True
    )
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    # risk_score is the normalized 0-100 score derived from anomaly_score
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True, index=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    network_event = relationship("NetworkEvent", back_populates="anomaly")
    analysis_run = relationship("AnalysisRun", back_populates="anomalies")
