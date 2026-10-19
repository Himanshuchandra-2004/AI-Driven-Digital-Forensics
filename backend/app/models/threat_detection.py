"""ThreatDetection model — Random Forest classification results."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID, JSONType


class ThreatDetection(Base):
    __tablename__ = "threat_detections"

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
    predicted_class: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)
    class_probabilities: Mapped[dict] = mapped_column(JSONType(), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True, index=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    network_event = relationship("NetworkEvent", back_populates="threat_detection")
    analysis_run = relationship("AnalysisRun", back_populates="threat_detections")
