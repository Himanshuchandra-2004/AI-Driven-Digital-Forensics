"""
Timeline & Network Graph API — forensic investigation views.

Provides:
- /api/cases/{case_id}/timeline — chronological event timeline
- /api/cases/{case_id}/network-graph — network topology data
- /api/cases/{case_id}/statistics — per-case detailed statistics
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import Role, require_role
from app.models.anomaly import Anomaly
from app.models.chain_of_custody import ChainOfCustody
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.network_event import NetworkEvent
from app.models.threat_detection import ThreatDetection
from app.models.user import User

router = APIRouter()


@router.get("/cases/{case_id}/timeline")
async def get_case_timeline(
    case_id: uuid.UUID,
    limit: int = Query(200, ge=1, le=1000),
    event_type: Optional[str] = Query(None, description="Filter: evidence|threat|anomaly|custody"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Chronological timeline of all forensic events for a case.
    
    Combines evidence extractions, threat detections, anomaly detections,
    and chain of custody events into a unified, time-ordered timeline.
    Each entry includes type, severity, description, and timestamp.
    """
    timeline = []

    # Evidence events
    if event_type is None or event_type == "evidence":
        ev_q = await db.execute(
            select(Evidence)
            .where(Evidence.case_id == case_id)
            .order_by(Evidence.extraction_timestamp.desc())
            .limit(limit)
        )
        for ev in ev_q.scalars().all():
            timeline.append({
                "type": "evidence",
                "subtype": ev.evidence_type,
                "id": str(ev.id),
                "timestamp": ev.extraction_timestamp.isoformat(),
                "severity": ev.severity,
                "risk_score": ev.risk_score,
                "description": (
                    f"Evidence extracted: {ev.evidence_type} — "
                    f"{ev.predicted_threat or 'Anomaly'} from {ev.src_ip or '?'} → {ev.dst_ip or '?'}"
                ),
                "src_ip": ev.src_ip,
                "dst_ip": ev.dst_ip,
                "src_port": ev.src_port,
                "dst_port": ev.dst_port,
                "protocol": ev.protocol,
                "hash": ev.evidence_hash,
            })

    # Threat detections
    if event_type is None or event_type == "threat":
        threat_q = await db.execute(
            select(ThreatDetection, NetworkEvent)
            .join(NetworkEvent, ThreatDetection.network_event_id == NetworkEvent.id)
            .where(ThreatDetection.case_id == case_id)
            .where(ThreatDetection.predicted_class != "BENIGN")
            .order_by(ThreatDetection.detected_at.desc())
            .limit(limit)
        )
        for threat, event in threat_q.all():
            timeline.append({
                "type": "threat",
                "subtype": threat.predicted_class,
                "id": str(threat.id),
                "timestamp": threat.detected_at.isoformat(),
                "severity": threat.severity,
                "risk_score": None,
                "description": (
                    f"Threat detected: {threat.predicted_class} "
                    f"(confidence: {threat.confidence:.1%}) "
                    f"from {event.src_ip or '?'} → {event.dst_ip or '?'}"
                ),
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "confidence": threat.confidence,
            })

    # Anomaly detections
    if event_type is None or event_type == "anomaly":
        anom_q = await db.execute(
            select(Anomaly, NetworkEvent)
            .join(NetworkEvent, Anomaly.network_event_id == NetworkEvent.id)
            .where(Anomaly.case_id == case_id)
            .where(Anomaly.is_anomaly == True)
            .order_by(Anomaly.detected_at.desc())
            .limit(limit)
        )
        for anomaly, event in anom_q.all():
            timeline.append({
                "type": "anomaly",
                "subtype": "isolation_forest",
                "id": str(anomaly.id),
                "timestamp": anomaly.detected_at.isoformat(),
                "severity": anomaly.severity,
                "risk_score": anomaly.risk_score,
                "description": (
                    f"Anomaly detected: score={anomaly.anomaly_score:.4f}, "
                    f"risk={anomaly.risk_score:.1f} "
                    f"from {event.src_ip or '?'} → {event.dst_ip or '?'}"
                ),
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "anomaly_score": anomaly.anomaly_score,
            })

    # Chain of custody events
    if event_type is None or event_type == "custody":
        custody_q = await db.execute(
            select(ChainOfCustody, User)
            .join(User, ChainOfCustody.user_id == User.id)
            .where(
                ChainOfCustody.evidence_id.in_(
                    select(Evidence.id).where(Evidence.case_id == case_id)
                )
            )
            .order_by(ChainOfCustody.timestamp.desc())
            .limit(limit)
        )
        for custody, user in custody_q.all():
            timeline.append({
                "type": "custody",
                "subtype": custody.action,
                "id": str(custody.id),
                "timestamp": custody.timestamp.isoformat(),
                "severity": None,
                "risk_score": None,
                "description": (
                    f"Chain of custody: {custody.action} by {user.username} — "
                    f"{custody.description or ''}"
                ),
                "user": user.username,
                "integrity_hash": custody.integrity_hash,
            })

    # Sort all events by timestamp (most recent first)
    timeline.sort(key=lambda e: e["timestamp"], reverse=True)

    return {
        "case_id": str(case_id),
        "total_events": len(timeline),
        "events": timeline[:limit],
    }


@router.get("/cases/{case_id}/network-graph")
async def get_network_graph(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Network topology graph data for visualization.
    
    Returns:
    - nodes: unique IPs with metadata (role, threat count, event count)
    - edges: IP-to-IP connections with weight and threat info
    
    Designed for force-directed graph rendering (e.g., react-force-graph-2d).
    """
    # Fetch all evidence for the case
    ev_q = await db.execute(
        select(Evidence).where(Evidence.case_id == case_id)
    )
    evidence_items = ev_q.scalars().all()

    # Build node and edge data
    nodes = {}  # ip -> metadata
    edges = defaultdict(lambda: {"count": 0, "threats": set(), "severities": set()})

    for ev in evidence_items:
        src = ev.src_ip or "unknown"
        dst = ev.dst_ip or "unknown"

        # Track source node
        if src not in nodes:
            nodes[src] = {
                "id": src,
                "label": src,
                "type": "source",
                "event_count": 0,
                "threat_count": 0,
                "max_severity": "low",
            }
        nodes[src]["event_count"] += 1
        if ev.predicted_threat and ev.predicted_threat.upper() != "BENIGN":
            nodes[src]["threat_count"] += 1

        # Track destination node
        if dst not in nodes:
            nodes[dst] = {
                "id": dst,
                "label": dst,
                "type": "destination",
                "event_count": 0,
                "threat_count": 0,
                "max_severity": "low",
            }
        nodes[dst]["event_count"] += 1

        # Track edge
        edge_key = f"{src}→{dst}"
        edges[edge_key]["count"] += 1
        if ev.predicted_threat:
            edges[edge_key]["threats"].add(ev.predicted_threat)
        if ev.severity:
            edges[edge_key]["severities"].add(ev.severity)

        # Update max severity
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if ev.severity:
            for node_ip in [src, dst]:
                current_sev = sev_order.get(nodes[node_ip]["max_severity"], 0)
                new_sev = sev_order.get(ev.severity, 0)
                if new_sev > current_sev:
                    nodes[node_ip]["max_severity"] = ev.severity

    # Determine node roles (both source and target)
    src_ips = set()
    dst_ips = set()
    for ev in evidence_items:
        if ev.src_ip:
            src_ips.add(ev.src_ip)
        if ev.dst_ip:
            dst_ips.add(ev.dst_ip)
    for ip, node in nodes.items():
        if ip in src_ips and ip in dst_ips:
            node["type"] = "both"
        elif ip in src_ips:
            node["type"] = "source"
        else:
            node["type"] = "destination"

    # Format edges
    formatted_edges = []
    for edge_key, data in edges.items():
        src, dst = edge_key.split("→")
        formatted_edges.append({
            "source": src,
            "target": dst,
            "weight": data["count"],
            "threats": list(data["threats"]),
            "max_severity": max(
                data["severities"],
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
                default="low",
            ) if data["severities"] else "low",
        })

    return {
        "case_id": str(case_id),
        "nodes": list(nodes.values()),
        "edges": formatted_edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(formatted_edges),
            "unique_sources": len(src_ips),
            "unique_destinations": len(dst_ips),
        },
    }


@router.get("/cases/{case_id}/statistics")
async def get_case_statistics(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Detailed per-case statistics for forensic analysis.
    
    Returns protocol breakdown, port distribution, temporal patterns,
    threat category distribution, and severity analysis.
    """
    # Protocol distribution
    proto_q = await db.execute(
        select(Evidence.protocol, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.protocol.isnot(None))
        .group_by(Evidence.protocol)
    )
    protocol_dist = {row[0]: row[1] for row in proto_q.all()}

    # Destination port distribution (top 15)
    port_q = await db.execute(
        select(Evidence.dst_port, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.dst_port.isnot(None))
        .group_by(Evidence.dst_port)
        .order_by(func.count(Evidence.id).desc())
        .limit(15)
    )
    port_dist = [{"port": row[0], "count": row[1]} for row in port_q.all()]

    # Threat category distribution
    threat_q = await db.execute(
        select(ThreatDetection.predicted_class, func.count(ThreatDetection.id))
        .where(ThreatDetection.case_id == case_id)
        .where(ThreatDetection.predicted_class != "BENIGN")
        .group_by(ThreatDetection.predicted_class)
        .order_by(func.count(ThreatDetection.id).desc())
    )
    threat_dist = {row[0]: row[1] for row in threat_q.all()}

    # Severity distribution
    sev_q = await db.execute(
        select(Evidence.severity, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.severity.isnot(None))
        .group_by(Evidence.severity)
    )
    severity_dist = {row[0]: row[1] for row in sev_q.all()}

    # Risk score statistics
    risk_q = await db.execute(
        select(
            func.min(Evidence.risk_score),
            func.max(Evidence.risk_score),
            func.avg(Evidence.risk_score),
            func.count(Evidence.id),
        )
        .where(Evidence.case_id == case_id)
        .where(Evidence.risk_score.isnot(None))
    )
    risk_row = risk_q.one()
    risk_stats = {
        "min": round(float(risk_row[0] or 0), 2),
        "max": round(float(risk_row[1] or 0), 2),
        "avg": round(float(risk_row[2] or 0), 2),
        "total_scored": risk_row[3] or 0,
    }

    # Top attackers (source IPs by threat count)
    attacker_q = await db.execute(
        select(Evidence.src_ip, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.src_ip.isnot(None))
        .where(Evidence.predicted_threat.isnot(None))
        .where(Evidence.predicted_threat != "BENIGN")
        .group_by(Evidence.src_ip)
        .order_by(func.count(Evidence.id).desc())
        .limit(10)
    )
    top_attackers = [{"ip": row[0], "threat_count": row[1]} for row in attacker_q.all()]

    # Top targets (destination IPs by event count)
    target_q = await db.execute(
        select(Evidence.dst_ip, func.count(Evidence.id))
        .where(Evidence.case_id == case_id)
        .where(Evidence.dst_ip.isnot(None))
        .group_by(Evidence.dst_ip)
        .order_by(func.count(Evidence.id).desc())
        .limit(10)
    )
    top_targets = [{"ip": row[0], "event_count": row[1]} for row in target_q.all()]

    # Incident summary
    inc_q = await db.execute(
        select(func.count(Incident.id))
        .where(Incident.case_id == case_id)
    )
    total_incidents = inc_q.scalar() or 0

    critical_inc_q = await db.execute(
        select(func.count(Incident.id))
        .where(Incident.case_id == case_id)
        .where(Incident.severity == "critical")
    )
    critical_incidents = critical_inc_q.scalar() or 0

    return {
        "case_id": str(case_id),
        "protocol_distribution": protocol_dist,
        "port_distribution": port_dist,
        "threat_category_distribution": threat_dist,
        "severity_distribution": severity_dist,
        "risk_score_statistics": risk_stats,
        "top_attackers": top_attackers,
        "top_targets": top_targets,
        "incident_summary": {
            "total": total_incidents,
            "critical": critical_incidents,
        },
    }
