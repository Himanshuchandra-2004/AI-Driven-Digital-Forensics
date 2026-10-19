"""EvidenceRelation model — links evidence to incidents."""

from __future__ import annotations

import uuid

from sqlalchemy import Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.types import GUID


class EvidenceRelation(Base):
    __tablename__ = "evidence_relations"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("evidence.id"), nullable=False, index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incidents.id"), nullable=False, index=True
    )
    relation_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="ip_correlation"
    )  # ip_correlation, temporal, threat_type, session
    correlation_score: Mapped[float] = mapped_column(Float, nullable=True, default=1.0)

    # Relationships
    evidence = relationship("Evidence", back_populates="evidence_relations")
    incident = relationship("Incident", back_populates="evidence_relations")
