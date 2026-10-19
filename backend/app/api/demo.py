"""Demo API — load demo case endpoint."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.user import User
from app.services.demo_service import create_demo_case

router = APIRouter()


@router.post("/load")
async def load_demo(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """
    Create a complete demo case with synthetic network data.
    Generates data, creates case, and starts analysis in background.
    """
    result = await create_demo_case(
        user_id=str(current_user.id),
        db=db,
    )

    # Run analysis in background
    from app.services.analysis_service import run_full_analysis

    background_tasks.add_task(
        run_full_analysis,
        result["analysis_run_id"],
        result["case_id"],
        result["demo_filename"],
        str(current_user.id),
    )

    return result
