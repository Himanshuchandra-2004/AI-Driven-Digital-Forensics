"""Incidents API — correlated evidence clusters."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.evidence_relation import EvidenceRelation
from app.models.incident import Incident
from app.models.user import User
from app.schemas import IncidentResponse

router = APIRouter()


@router.get("/cases/{case_id}/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all incidents (correlated evidence clusters) for a case."""
    result = await db.execute(
        select(Incident)
        .where(Incident.case_id == case_id)
        .order_by(Incident.risk_score.desc().nullslast())
    )
    incidents = result.scalars().all()

    responses = []
    for inc in incidents:
        resp = IncidentResponse.model_validate(inc)
        # Attach evidence IDs
        rel_result = await db.execute(
            select(EvidenceRelation.evidence_id)
            .where(EvidenceRelation.incident_id == inc.id)
        )
        resp.evidence_ids = [r for r in rel_result.scalars().all()]
        responses.append(resp)
    return responses


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get detailed incident with related evidence IDs."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    resp = IncidentResponse.model_validate(inc)
    rel_result = await db.execute(
        select(EvidenceRelation.evidence_id)
        .where(EvidenceRelation.incident_id == inc.id)
    )
    resp.evidence_ids = [r for r in rel_result.scalars().all()]
    return resp
