"""Dashboard API — aggregated statistics from real data."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.anomaly import Anomaly
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.threat_detection import ThreatDetection
from app.models.user import User
from app.schemas import CaseResponse, DashboardStats

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """Get aggregated dashboard statistics from real backend data."""

    # Total and active cases
    total_cases_q = await db.execute(select(func.count(Case.id)))
    total_cases = total_cases_q.scalar() or 0

    active_cases_q = await db.execute(
        select(func.count(Case.id)).where(Case.status.in_(["open", "analyzing"]))
    )
    active_cases = active_cases_q.scalar() or 0

    # Total evidence
    total_evidence_q = await db.execute(select(func.count(Evidence.id)))
    total_evidence = total_evidence_q.scalar() or 0

    # Total threats (non-benign)
    total_threats_q = await db.execute(
        select(func.count(ThreatDetection.id))
        .where(ThreatDetection.predicted_class != "BENIGN")
    )
    total_threats = total_threats_q.scalar() or 0

    # Total anomalies
    total_anomalies_q = await db.execute(
        select(func.count(Anomaly.id)).where(Anomaly.is_anomaly == True)
    )
    total_anomalies = total_anomalies_q.scalar() or 0

    # Critical and high incidents
    critical_q = await db.execute(
        select(func.count(Incident.id)).where(Incident.severity == "critical")
    )
    critical_incidents = critical_q.scalar() or 0

    high_q = await db.execute(
        select(func.count(Incident.id)).where(Incident.severity == "high")
    )
    high_incidents = high_q.scalar() or 0

    # Threat distribution
    threat_dist_q = await db.execute(
        select(ThreatDetection.predicted_class, func.count(ThreatDetection.id))
        .where(ThreatDetection.predicted_class != "BENIGN")
        .group_by(ThreatDetection.predicted_class)
    )
    threat_distribution = {row[0]: row[1] for row in threat_dist_q.all()}

    # Severity distribution
    sev_dist_q = await db.execute(
        select(Evidence.severity, func.count(Evidence.id))
        .where(Evidence.severity.isnot(None))
        .group_by(Evidence.severity)
    )
    severity_distribution = {row[0]: row[1] for row in sev_dist_q.all()}

    # Top source IPs
    top_src_q = await db.execute(
        select(Evidence.src_ip, func.count(Evidence.id).label("count"))
        .where(Evidence.src_ip.isnot(None))
        .group_by(Evidence.src_ip)
        .order_by(func.count(Evidence.id).desc())
        .limit(10)
    )
    top_source_ips = [{"ip": r[0], "count": r[1]} for r in top_src_q.all()]

    # Top destination IPs
    top_dst_q = await db.execute(
        select(Evidence.dst_ip, func.count(Evidence.id).label("count"))
        .where(Evidence.dst_ip.isnot(None))
        .group_by(Evidence.dst_ip)
        .order_by(func.count(Evidence.id).desc())
        .limit(10)
    )
    top_dest_ips = [{"ip": r[0], "count": r[1]} for r in top_dst_q.all()]

    # Recent cases
    recent_q = await db.execute(
        select(Case).order_by(Case.created_at.desc()).limit(5)
    )
    recent_cases = [CaseResponse.model_validate(c) for c in recent_q.scalars().all()]

    return DashboardStats(
        total_cases=total_cases,
        active_cases=active_cases,
        total_evidence=total_evidence,
        total_threats=total_threats,
        total_anomalies=total_anomalies,
        critical_incidents=critical_incidents,
        high_incidents=high_incidents,
        threat_distribution=threat_distribution,
        severity_distribution=severity_distribution,
        top_source_ips=top_source_ips,
        top_dest_ips=top_dest_ips,
        recent_cases=recent_cases,
    )
