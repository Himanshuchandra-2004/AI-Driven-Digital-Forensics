"""Reports API — generate and download forensic reports."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.case import Case
from app.models.report import Report
from app.models.user import User
from app.schemas import ReportGenerateRequest, ReportResponse

router = APIRouter()


@router.get("/cases/{case_id}/reports", response_model=list[ReportResponse])
async def list_reports(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all generated reports for a case."""
    result = await db.execute(
        select(Report)
        .where(Report.case_id == case_id)
        .order_by(Report.generated_at.desc())
    )
    reports = result.scalars().all()
    return [ReportResponse.model_validate(r) for r in reports]


@router.post("/cases/{case_id}/report", response_model=ReportResponse)
async def generate_report(
    case_id: uuid.UUID,
    request: ReportGenerateRequest = ReportGenerateRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Generate a forensic report for a case."""
    from app.services.report_service import generate_forensic_report

    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    report = await generate_forensic_report(
        case_id=str(case_id),
        user_id=str(current_user.id),
        report_type=request.report_type,
        db=db,
    )
    return ReportResponse.model_validate(report)


@router.get("/reports/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get report metadata."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.model_validate(report)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Download a generated report file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not available")

    media_types = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
    }

    return FileResponse(
        path=report.file_path,
        media_type=media_types.get(report.report_type, "application/octet-stream"),
        filename=f"forensic_report_{report.case_id}.{report.report_type}",
    )
