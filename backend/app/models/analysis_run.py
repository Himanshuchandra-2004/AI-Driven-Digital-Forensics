"""AnalysisRun model — tracks each analysis execution."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID, JSONType


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="queued"
    )  # queued, processing, completed, failed
    source_file: Mapped[str] = mapped_column(String(500), nullable=True)
    source_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="csv"
    )  # csv, pcap, log
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_records: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_count: Mapped[int] = mapped_column(Integer, default=0)
    preprocessing_time: Mapped[float] = mapped_column(Float, nullable=True)
    feature_extraction_time: Mapped[float] = mapped_column(Float, nullable=True)
    inference_time: Mapped[float] = mapped_column(Float, nullable=True)
    total_time: Mapped[float] = mapped_column(Float, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    metrics: Mapped[dict] = mapped_column(JSONType(), nullable=True)  # model metrics snapshot
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    case = relationship("Case", back_populates="analysis_runs", lazy="selectin")
    network_events = relationship("NetworkEvent", back_populates="analysis_run", lazy="selectin")
    threat_detections = relationship("ThreatDetection", back_populates="analysis_run", lazy="selectin")
    anomalies = relationship("Anomaly", back_populates="analysis_run", lazy="selectin")
