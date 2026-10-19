"""NetworkEvent model — individual network flow records from analysis."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID, JSONType


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("analysis_runs.id"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id"), nullable=False, index=True
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=True)
    duration: Mapped[float] = mapped_column(Float, nullable=True)
    total_fwd_packets: Mapped[int] = mapped_column(Integer, nullable=True)
    total_bwd_packets: Mapped[int] = mapped_column(Integer, nullable=True)
    flow_bytes_per_s: Mapped[float] = mapped_column(Float, nullable=True)
    flow_packets_per_s: Mapped[float] = mapped_column(Float, nullable=True)
    raw_features: Mapped[dict] = mapped_column(JSONType(), nullable=True)
    row_index: Mapped[int] = mapped_column(Integer, nullable=True)  # row in uploaded CSV

    # Relationships
    analysis_run = relationship("AnalysisRun", back_populates="network_events")
    threat_detection = relationship("ThreatDetection", back_populates="network_event", uselist=False)
    anomaly = relationship("Anomaly", back_populates="network_event", uselist=False)
