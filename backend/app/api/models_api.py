"""Models API — view trained model metadata and metrics."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.model_version import ModelVersion
from app.models.user import User
from app.schemas import ModelVersionResponse

router = APIRouter()


@router.get("", response_model=list[ModelVersionResponse])
async def list_models(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all trained model versions with their metrics."""
    result = await db.execute(
        select(ModelVersion).order_by(ModelVersion.trained_at.desc())
    )
    models = result.scalars().all()
    return [ModelVersionResponse.model_validate(m) for m in models]


@router.get("/{model_id}", response_model=ModelVersionResponse)
async def get_model(
    model_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get detailed model version information."""
    result = await db.execute(select(ModelVersion).where(ModelVersion.id == model_id))
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model version not found")
    return ModelVersionResponse.model_validate(model)
