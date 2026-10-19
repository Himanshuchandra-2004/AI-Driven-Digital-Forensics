"""Analysis API — trigger analysis, view results."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, get_current_user, require_role
from app.models.analysis_run import AnalysisRun
from app.models.case import Case
from app.models.user import User
from app.schemas import AnalysisRunResponse

router = APIRouter()


@router.post("/cases/{case_id}/analyze", response_model=AnalysisRunResponse)
async def start_analysis(
    case_id: uuid.UUID,
    filename: str = "",
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Start an analysis run on uploaded data for a case."""
    # Verify case exists and belongs to user
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if current_user.role != "admin" and case.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Create analysis run record
    analysis_run = AnalysisRun(
        case_id=case_id,
        status="queued",
        source_file=filename if filename else None,
        source_type="csv",
    )
    db.add(analysis_run)
    await db.flush()
    await db.refresh(analysis_run)

    # Update case status
    case.status = "analyzing"
    await db.flush()

    # Schedule background analysis
    background_tasks.add_task(
        _run_analysis_background,
        str(analysis_run.id),
        str(case_id),
        filename,
        str(current_user.id),
    )

    return AnalysisRunResponse.model_validate(analysis_run)


@router.get("/cases/{case_id}/analysis", response_model=list[AnalysisRunResponse])
async def list_analysis_runs(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all analysis runs for a case."""
    result = await db.execute(
        select(AnalysisRun)
        .where(AnalysisRun.case_id == case_id)
        .order_by(AnalysisRun.started_at.desc())
    )
    runs = result.scalars().all()
    return [AnalysisRunResponse.model_validate(r) for r in runs]


@router.get("/analysis/{run_id}", response_model=AnalysisRunResponse)
async def get_analysis_run(
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get details of a specific analysis run."""
    result = await db.execute(select(AnalysisRun).where(AnalysisRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return AnalysisRunResponse.model_validate(run)


async def _run_analysis_background(
    analysis_run_id: str,
    case_id: str,
    filename: str,
    user_id: str,
):
    """Background task that runs the full ML analysis pipeline.
    
    This is implemented fully in Phase 8 (ML/Backend integration).
    The import is deferred to avoid circular dependencies during early phases.
    """
    from app.services.analysis_service import run_full_analysis
    await run_full_analysis(analysis_run_id, case_id, filename, user_id)
