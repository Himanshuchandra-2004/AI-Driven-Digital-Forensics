"""Evidence API — list, view, verify integrity, chain of custody."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, get_current_user, require_role
from app.models.anomaly import Anomaly
from app.models.chain_of_custody import ChainOfCustody
from app.models.evidence import Evidence
from app.models.threat_detection import ThreatDetection
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas import (
    AnomalyResponse,
    ChainOfCustodyResponse,
    EvidenceResponse,
    EvidenceVerifyResponse,
    ThreatDetectionResponse,
)

router = APIRouter()


# ---- Evidence ----
@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceResponse])
async def list_evidence(
    case_id: uuid.UUID,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List evidence for a case with filtering and pagination."""
    query = select(Evidence).where(Evidence.case_id == case_id)
    if severity:
        query = query.where(Evidence.severity == severity)
    if threat_type:
        query = query.where(Evidence.predicted_threat == threat_type)
    if src_ip:
        query = query.where(Evidence.src_ip == src_ip)
    if dst_ip:
        query = query.where(Evidence.dst_ip == dst_ip)

    query = query.order_by(Evidence.extraction_timestamp.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    items = result.scalars().all()
    return [EvidenceResponse.model_validate(e) for e in items]


@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get detailed evidence record."""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return EvidenceResponse.model_validate(evidence)


@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceVerifyResponse)
async def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """Verify evidence integrity by recalculating and comparing SHA-256 hash."""
    from app.services.hash_service import verify_evidence_hash

    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    verification = verify_evidence_hash(evidence)

    # Record verification in chain of custody
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action="verified",
        description=f"Integrity verification: {verification['message']}",
        integrity_hash=verification["calculated_hash"],
    )
    db.add(custody)

    return EvidenceVerifyResponse(
        evidence_id=evidence.id,
        integrity_verified=verification["verified"],
        stored_hash=verification["stored_hash"],
        calculated_hash=verification["calculated_hash"],
        message=verification["message"],
    )


# ---- Threats ----
@router.get("/cases/{case_id}/threats", response_model=list[ThreatDetectionResponse])
async def list_threats(
    case_id: uuid.UUID,
    severity: Optional[str] = None,
    predicted_class: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List threat detections for a case."""
    query = (
        select(ThreatDetection, NetworkEvent)
        .join(NetworkEvent, ThreatDetection.network_event_id == NetworkEvent.id)
        .where(ThreatDetection.case_id == case_id)
        .where(ThreatDetection.predicted_class != "BENIGN")
    )
    if severity:
        query = query.where(ThreatDetection.severity == severity)
    if predicted_class:
        query = query.where(ThreatDetection.predicted_class == predicted_class)

    query = query.order_by(ThreatDetection.detected_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    rows = result.all()

    responses = []
    for threat, event in rows:
        resp = ThreatDetectionResponse.model_validate(threat)
        resp.src_ip = event.src_ip
        resp.dst_ip = event.dst_ip
        resp.src_port = event.src_port
        resp.dst_port = event.dst_port
        resp.protocol = event.protocol
        responses.append(resp)
    return responses


@router.get("/threats/{threat_id}", response_model=ThreatDetectionResponse)
async def get_threat(
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get a specific threat detection."""
    result = await db.execute(
        select(ThreatDetection, NetworkEvent)
        .join(NetworkEvent, ThreatDetection.network_event_id == NetworkEvent.id)
        .where(ThreatDetection.id == threat_id)
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Threat detection not found")
    threat, event = row
    resp = ThreatDetectionResponse.model_validate(threat)
    resp.src_ip = event.src_ip
    resp.dst_ip = event.dst_ip
    resp.src_port = event.src_port
    resp.dst_port = event.dst_port
    resp.protocol = event.protocol
    return resp


# ---- Anomalies ----
@router.get("/cases/{case_id}/anomalies", response_model=list[AnomalyResponse])
async def list_anomalies(
    case_id: uuid.UUID,
    is_anomaly: Optional[bool] = True,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """List anomaly detections for a case."""
    query = (
        select(Anomaly, NetworkEvent)
        .join(NetworkEvent, Anomaly.network_event_id == NetworkEvent.id)
        .where(Anomaly.case_id == case_id)
    )
    if is_anomaly is not None:
        query = query.where(Anomaly.is_anomaly == is_anomaly)
    if severity:
        query = query.where(Anomaly.severity == severity)

    query = query.order_by(Anomaly.risk_score.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    rows = result.all()

    responses = []
    for anomaly, event in rows:
        resp = AnomalyResponse.model_validate(anomaly)
        resp.src_ip = event.src_ip
        resp.dst_ip = event.dst_ip
        resp.src_port = event.src_port
        resp.dst_port = event.dst_port
        resp.protocol = event.protocol
        responses.append(resp)
    return responses


# ---- Chain of Custody ----
@router.get("/evidence/{evidence_id}/custody", response_model=list[ChainOfCustodyResponse])
async def get_chain_of_custody(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get the chain of custody timeline for evidence."""
    result = await db.execute(
        select(ChainOfCustody, User)
        .join(User, ChainOfCustody.user_id == User.id)
        .where(ChainOfCustody.evidence_id == evidence_id)
        .order_by(ChainOfCustody.timestamp.asc())
    )
    rows = result.all()
    responses = []
    for custody, user in rows:
        resp = ChainOfCustodyResponse.model_validate(custody)
        resp.username = user.username
        responses.append(resp)
    return responses


# ---- Enriched Evidence ----
@router.get("/evidence/{evidence_id}/enriched")
async def get_enriched_evidence(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Get evidence with full intelligence enrichment.
    
    Includes IP classification (private/public/RFC), port service info,
    protocol resolution, MITRE ATT&CK threat context, and risk factors.
    """
    from app.services.enrichment_service import enrich_evidence

    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    base = EvidenceResponse.model_validate(evidence).model_dump()
    enrichment = enrich_evidence(evidence)

    return {
        **base,
        "enrichment": enrichment,
    }


# ---- Evidence Summary ----
@router.get("/cases/{case_id}/evidence/summary")
async def get_evidence_summary(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Aggregated evidence statistics for a case.
    
    Returns total counts, severity breakdown, threat type distribution,
    unique IP counts, and integrity verification status.
    """
    # Total evidence
    total_q = await db.execute(
        select(func.count(Evidence.id)).where(Evidence.case_id == case_id)
    )
    total = total_q.scalar() or 0

    # Severity breakdown
    sev_q = await db.execute(
        select(Evidence.severity, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.severity.isnot(None))
        .group_by(Evidence.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in sev_q.all()}

    # Evidence type breakdown
    type_q = await db.execute(
        select(Evidence.evidence_type, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .group_by(Evidence.evidence_type)
    )
    type_breakdown = {row[0]: row[1] for row in type_q.all()}

    # Threat type distribution
    threat_q = await db.execute(
        select(Evidence.predicted_threat, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.predicted_threat.isnot(None))
        .group_by(Evidence.predicted_threat)
    )
    threat_dist = {row[0]: row[1] for row in threat_q.all()}

    # Unique IPs
    src_ip_q = await db.execute(
        select(func.count(func.distinct(Evidence.src_ip)))
        .where(Evidence.case_id == case_id)
        .where(Evidence.src_ip.isnot(None))
    )
    unique_src_ips = src_ip_q.scalar() or 0

    dst_ip_q = await db.execute(
        select(func.count(func.distinct(Evidence.dst_ip)))
        .where(Evidence.case_id == case_id)
        .where(Evidence.dst_ip.isnot(None))
    )
    unique_dst_ips = dst_ip_q.scalar() or 0

    # Hashed vs unhashed
    hashed_q = await db.execute(
        select(func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.evidence_hash.isnot(None))
    )
    hashed_count = hashed_q.scalar() or 0

    # Risk score stats
    risk_q = await db.execute(
        select(
            func.min(Evidence.risk_score),
            func.max(Evidence.risk_score),
            func.avg(Evidence.risk_score),
        )
        .where(Evidence.case_id == case_id)
        .where(Evidence.risk_score.isnot(None))
    )
    risk_row = risk_q.one()

    return {
        "case_id": str(case_id),
        "total_evidence": total,
        "severity_breakdown": severity_breakdown,
        "type_breakdown": type_breakdown,
        "threat_distribution": threat_dist,
        "unique_source_ips": unique_src_ips,
        "unique_destination_ips": unique_dst_ips,
        "integrity": {
            "hashed": hashed_count,
            "unhashed": total - hashed_count,
            "coverage_pct": round((hashed_count / total) * 100, 1) if total > 0 else 0,
        },
        "risk_scores": {
            "min": round(float(risk_row[0] or 0), 2),
            "max": round(float(risk_row[1] or 0), 2),
            "avg": round(float(risk_row[2] or 0), 2),
        },
    }


# ---- Evidence Export ----
@router.get("/cases/{case_id}/evidence/export")
async def export_evidence(
    case_id: uuid.UUID,
    format: str = Query("json", pattern="^(json|csv)$"),
    severity: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.INVESTIGATOR)),
):
    """
    Export evidence records in JSON or CSV format.
    
    Supports filtering by severity and limiting result count.
    Returns the data directly (not as a file download) for API consumers.
    """
    query = select(Evidence).where(Evidence.case_id == case_id)
    if severity:
        query = query.where(Evidence.severity == severity)
    query = query.order_by(Evidence.risk_score.desc().nullslast()).limit(limit)

    result = await db.execute(query)
    items = result.scalars().all()

    records = []
    for ev in items:
        records.append({
            "evidence_id": str(ev.id),
            "evidence_type": ev.evidence_type,
            "predicted_threat": ev.predicted_threat,
            "anomaly_score": ev.anomaly_score,
            "classification_confidence": ev.classification_confidence,
            "severity": ev.severity,
            "risk_score": ev.risk_score,
            "src_ip": ev.src_ip,
            "dst_ip": ev.dst_ip,
            "src_port": ev.src_port,
            "dst_port": ev.dst_port,
            "protocol": ev.protocol,
            "evidence_hash": ev.evidence_hash,
            "status": ev.status,
            "extraction_timestamp": ev.extraction_timestamp.isoformat() if ev.extraction_timestamp else None,
        })

    if format == "csv":
        import csv
        import io
        from fastapi.responses import StreamingResponse

        if not records:
            records = [{"message": "No evidence found"}]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=evidence_{case_id}.csv"
            },
        )

    return {
        "case_id": str(case_id),
        "total_exported": len(records),
        "format": format,
        "records": records,
    }
