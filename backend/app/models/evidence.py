"""Evidence model — forensic evidence extracted from suspicious events."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID, JSONType


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id"), nullable=False, index=True
    )
    network_event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("network_events.id"), nullable=True
    )
    threat_detection_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat_detections.id"), nullable=True
    )
    anomaly_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("anomalies.id"), nullable=True
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="network_flow"
    )  # network_flow, anomaly, threat, combined
    predicted_threat: Mapped[str] = mapped_column(String(100), nullable=True)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=True)
    classification_confidence: Mapped[float] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=True)
    source_file: Mapped[str] = mapped_column(String(500), nullable=True)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="active"
    )  # active, verified, archived
    extraction_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    metadata_json: Mapped[dict] = mapped_column(JSONType(), nullable=True)

    # Relationships
    case = relationship("Case", back_populates="evidence")
    chain_of_custody = relationship("ChainOfCustody", back_populates="evidence", lazy="selectin")
    evidence_relations = relationship("EvidenceRelation", back_populates="evidence", lazy="selectin")
