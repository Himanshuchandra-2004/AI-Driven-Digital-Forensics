"""ModelVersion model — tracks trained ML model metadata and metrics."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.types import GUID, JSONType


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    algorithm: Mapped[str] = mapped_column(String(100), nullable=False)  # isolation_forest, random_forest
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")
    dataset_name: Mapped[str] = mapped_column(String(200), nullable=True)
    features: Mapped[dict] = mapped_column(JSONType(), nullable=True)  # list of feature names
    metrics: Mapped[dict] = mapped_column(JSONType(), nullable=True)  # accuracy, f1, etc.
    parameters: Mapped[dict] = mapped_column(JSONType(), nullable=True)  # model hyperparameters
    model_path: Mapped[str] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )  # active, archived
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
