"""Cases API — CRUD operations and file upload."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import settings
from app.core.database import get_db
from app.core.dependencies import Role, get_current_user, require_role
from app.models.case import Case
from app.models.user import User
from app.schemas import CaseCreate, CaseResponse, CaseUpdate

router = APIRouter()

ALLOWED_EXTENSIONS = {".csv", ".pcap", ".log", ".txt"}


@router.get("", response_model=list[CaseResponse])
async def list_cases(
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List all cases accessible to the current user."""
    query = select(Case).order_by(Case.created_at.desc())
    if status_filter:
        query = query.where(Case.status == status_filter)
    # Non-admin users see only their own cases
    if current_user.role != Role.ADMIN:
        query = query.where(Case.user_id == current_user.id)

    result = await db.execute(query)
    cases = result.scalars().all()
    responses = []
    for c in cases:
        resp = CaseResponse.model_validate(c)
        resp.investigator = c.user.full_name if c.user else None
        responses.append(resp)
    return responses


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    data: CaseCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Create a new forensic case."""
    case = Case(
        user_id=current_user.id,
        name=data.name,
        description=data.description,
    )
    db.add(case)
    await db.flush()
    await db.refresh(case)
    resp = CaseResponse.model_validate(case)
    resp.investigator = current_user.full_name
    return resp


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get a specific case by ID."""
    case = await _get_case_or_404(case_id, db, current_user)
    resp = CaseResponse.model_validate(case)
    resp.investigator = case.user.full_name if case.user else None
    return resp


@router.put("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: uuid.UUID,
    data: CaseUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Update case details."""
    case = await _get_case_or_404(case_id, db, current_user)
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(case, key, value)
    await db.flush()
    await db.refresh(case)
    resp = CaseResponse.model_validate(case)
    resp.investigator = case.user.full_name if case.user else None
    return resp


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    """Delete a case (admin only)."""
    case = await _get_case_or_404(case_id, db, current_user)
    await db.delete(case)


@router.post("/{case_id}/upload")
async def upload_file(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Upload a network data file (CSV, PCAP, LOG) to a case."""
    case = await _get_case_or_404(case_id, db, current_user)

    # Validate file extension
    if file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"File type '{ext}' not allowed. Accepted: {ALLOWED_EXTENSIONS}",
            )
    else:
        raise HTTPException(status_code=400, detail="Filename required")

    # Validate file size
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit",
        )

    # Save with internal UUID filename
    internal_name = f"{uuid.uuid4()}{ext}"
    save_path = settings.upload_path / internal_name
    save_path.write_bytes(content)

    return {
        "message": "File uploaded successfully",
        "filename": file.filename,
        "internal_name": internal_name,
        "size_bytes": len(content),
        "case_id": str(case.id),
    }


@router.post("/{case_id}/upload-and-analyze")
async def upload_and_analyze(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """
    Upload a file and immediately start analysis.
    
    Supports CSV (network flow data) and PCAP files.
    PCAP files are automatically parsed into flow records via Scapy
    before being passed to the ML analysis pipeline.
    """
    import logging

    logger = logging.getLogger("forensics.cases")

    case = await _get_case_or_404(case_id, db, current_user)

    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename required")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' not allowed. Accepted: {ALLOWED_EXTENSIONS}",
        )

    # Validate file size
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit",
        )

    # Save uploaded file
    internal_name = f"{uuid.uuid4()}{ext}"
    save_path = settings.upload_path / internal_name
    save_path.write_bytes(content)

    analysis_filename = internal_name

    # Auto-detect PCAP and convert to CSV flows
    if ext == ".pcap":
        logger.info("PCAP file detected — converting to network flows via Scapy")
        try:
            from app.services.pcap_service import parse_pcap

            flow_df = parse_pcap(save_path)
            csv_name = f"{uuid.uuid4()}.csv"
            csv_path = settings.upload_path / csv_name
            flow_df.to_csv(csv_path, index=False)
            analysis_filename = csv_name
            logger.info(
                "PCAP converted: %d flows extracted → %s",
                len(flow_df),
                csv_name,
            )
        except Exception as e:
            logger.error("PCAP conversion failed: %s", e)
            raise HTTPException(
                status_code=422,
                detail=f"PCAP parsing failed: {str(e)}",
            )

    # Create analysis run
    from app.models.analysis_run import AnalysisRun

    analysis_run = AnalysisRun(
        case_id=case_id,
        status="queued",
        source_file=analysis_filename,
        source_type="pcap" if ext == ".pcap" else "csv",
    )
    db.add(analysis_run)

    # Update case status
    case.status = "analyzing"

    await db.flush()
    await db.refresh(analysis_run)

    # Schedule background analysis
    from app.services.analysis_service import run_full_analysis

    background_tasks.add_task(
        run_full_analysis,
        str(analysis_run.id),
        str(case_id),
        analysis_filename,
        str(current_user.id),
    )

    return {
        "message": "File uploaded and analysis started",
        "filename": file.filename,
        "internal_name": internal_name,
        "analysis_filename": analysis_filename,
        "size_bytes": len(content),
        "case_id": str(case.id),
        "analysis_run_id": str(analysis_run.id),
        "source_type": "pcap" if ext == ".pcap" else "csv",
        "pcap_converted": ext == ".pcap",
    }


async def _get_case_or_404(
    case_id: uuid.UUID,
    db: AsyncSession,
    current_user: User,
) -> Case:
    """Fetch a case by ID, enforcing access control."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if current_user.role != Role.ADMIN and case.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied to this case")
    return case
