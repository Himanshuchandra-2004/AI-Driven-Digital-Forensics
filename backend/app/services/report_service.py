"""
Forensic Report Generation Service.

Generates professional forensic reports in PDF, JSON, and CSV formats.
Reports include actual data — never fabricated.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def generate_forensic_report(
    case_id: str,
    user_id: str,
    report_type: str,
    db: AsyncSession,
):
    """Generate a forensic report for a case."""
    from app.models.case import Case
    from app.models.analysis_run import AnalysisRun
    from app.models.evidence import Evidence
    from app.models.threat_detection import ThreatDetection
    from app.models.anomaly import Anomaly
    from app.models.incident import Incident
    from app.models.chain_of_custody import ChainOfCustody
    from app.models.user import User
    from app.models.report import Report
    from app.core import settings

    # Gather all data
    case_result = await db.execute(select(Case).where(Case.id == case_id))
    case = case_result.scalar_one()

    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one()

    # Analysis runs
    runs_result = await db.execute(
        select(AnalysisRun).where(AnalysisRun.case_id == case_id)
    )
    runs = runs_result.scalars().all()

    # Evidence
    evidence_result = await db.execute(
        select(Evidence).where(Evidence.case_id == case_id)
    )
    evidence_items = evidence_result.scalars().all()

    # Threats
    threats_result = await db.execute(
        select(ThreatDetection)
        .where(ThreatDetection.case_id == case_id)
        .where(ThreatDetection.predicted_class != "BENIGN")
    )
    threats = threats_result.scalars().all()

    # Anomalies
    anomalies_result = await db.execute(
        select(Anomaly)
        .where(Anomaly.case_id == case_id)
        .where(Anomaly.is_anomaly == True)
    )
    anomalies = anomalies_result.scalars().all()

    # Incidents
    incidents_result = await db.execute(
        select(Incident).where(Incident.case_id == case_id)
    )
    incidents = incidents_result.scalars().all()

    # Chain of custody
    custody_result = await db.execute(
        select(ChainOfCustody, User)
        .join(User, ChainOfCustody.user_id == User.id)
        .where(
            ChainOfCustody.evidence_id.in_([e.id for e in evidence_items])
            if evidence_items else ChainOfCustody.id == None
        )
        .order_by(ChainOfCustody.timestamp.asc())
    )
    custody_records = custody_result.all()

    # Build report data
    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "id": str(case.id),
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "severity": case.severity,
            "created_at": case.created_at.isoformat() if case.created_at else None,
        },
        "investigator": {
            "name": user.full_name,
            "username": user.username,
        },
        "analysis_summary": {
            "total_analyses": len(runs),
            "total_records_analyzed": sum(r.total_records for r in runs),
            "total_suspicious": sum(r.suspicious_records for r in runs),
            "total_anomalies": len(anomalies),
            "total_threats": len(threats),
            "total_evidence": len(evidence_items),
            "total_incidents": len(incidents),
        },
        "threat_classifications": {},
        "top_source_ips": [],
        "top_destination_ips": [],
        "incidents": [],
        "evidence_list": [],
        "integrity_verification": [],
        "chain_of_custody": [],
        "model_information": {},
        "conclusions": [],
    }

    # Threat distribution
    threat_dist = {}
    for t in threats:
        threat_dist[t.predicted_class] = threat_dist.get(t.predicted_class, 0) + 1
    report_data["threat_classifications"] = threat_dist

    # Top IPs
    src_ip_counts = {}
    dst_ip_counts = {}
    for e in evidence_items:
        if e.src_ip:
            src_ip_counts[e.src_ip] = src_ip_counts.get(e.src_ip, 0) + 1
        if e.dst_ip:
            dst_ip_counts[e.dst_ip] = dst_ip_counts.get(e.dst_ip, 0) + 1
    report_data["top_source_ips"] = sorted(
        [{"ip": k, "count": v} for k, v in src_ip_counts.items()],
        key=lambda x: -x["count"],
    )[:10]
    report_data["top_destination_ips"] = sorted(
        [{"ip": k, "count": v} for k, v in dst_ip_counts.items()],
        key=lambda x: -x["count"],
    )[:10]

    # Incidents
    for inc in incidents:
        report_data["incidents"].append({
            "name": inc.name,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "event_count": inc.event_count,
            "involved_ips": inc.involved_ips,
            "threat_categories": inc.threat_categories,
        })

    # Evidence with hashes
    for e in evidence_items[:50]:  # Limit for report size
        report_data["evidence_list"].append({
            "id": str(e.id),
            "type": e.evidence_type,
            "threat": e.predicted_threat,
            "severity": e.severity,
            "risk_score": e.risk_score,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "hash": e.evidence_hash,
        })

    # Chain of custody
    for custody, cust_user in custody_records[:100]:
        report_data["chain_of_custody"].append({
            "action": custody.action,
            "user": cust_user.username,
            "timestamp": custody.timestamp.isoformat() if custody.timestamp else None,
            "description": custody.description,
        })

    # Analysis metrics
    if runs:
        latest_run = runs[-1]
        report_data["model_information"] = latest_run.metrics or {}

    # Conclusions (data-driven, never fabricated)
    conclusions = []
    if len(threats) > 0:
        conclusions.append(
            f"Analysis identified {len(threats)} threat detections across "
            f"{len(threat_dist)} categories."
        )
    if len(anomalies) > 0:
        conclusions.append(
            f"Isolation Forest detected {len(anomalies)} anomalous network flows "
            f"that deviate from normal traffic patterns."
        )
    if len(incidents) > 0:
        conclusions.append(
            f"{len(incidents)} correlated incidents were identified, "
            f"grouping related suspicious events."
        )
    if not threats and not anomalies:
        conclusions.append("No significant threats or anomalies were detected in the analyzed data.")
    conclusions.append(
        "Note: This is an automated analysis by an academic prototype. "
        "Results should be reviewed by qualified investigators before any conclusions are drawn. "
        "This system does not establish legal guilt or definitive attacker attribution."
    )
    report_data["conclusions"] = conclusions

    # Generate output file
    reports_dir = settings.reports_path
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_id = str(uuid.uuid4())

    if report_type == "pdf":
        file_path = reports_dir / f"report_{report_id}.pdf"
        _generate_pdf(report_data, file_path)
    elif report_type == "json":
        file_path = reports_dir / f"report_{report_id}.json"
        with open(file_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
    elif report_type == "csv":
        file_path = reports_dir / f"report_{report_id}.csv"
        _generate_csv(report_data, file_path)
    else:
        file_path = reports_dir / f"report_{report_id}.json"
        with open(file_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

    # Save report record
    report = Report(
        case_id=uuid.UUID(case_id),
        user_id=uuid.UUID(user_id),
        report_type=report_type,
        file_path=str(file_path),
        report_data=report_data,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Chain of custody for report generation
    for e in evidence_items[:10]:
        custody = ChainOfCustody(
            evidence_id=e.id,
            user_id=uuid.UUID(user_id),
            action="report_generated",
            description=f"Forensic report generated ({report_type})",
            integrity_hash=e.evidence_hash,
        )
        db.add(custody)

    logger.info(f"Report generated: {file_path}")
    return report


def _generate_pdf(report_data: Dict[str, Any], file_path: Path):
    """Generate a professional PDF forensic report using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(str(file_path), pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=20,
    )
    elements.append(Paragraph("AI-Driven Digital Forensics — Network Forensics Report", title_style))
    elements.append(Spacer(1, 12))

    # Case Information
    elements.append(Paragraph("Case Information", styles["Heading2"]))
    case_info = report_data.get("case", {})
    case_table_data = [
        ["Field", "Value"],
        ["Case ID", case_info.get("id", "N/A")],
        ["Case Name", case_info.get("name", "N/A")],
        ["Status", case_info.get("status", "N/A")],
        ["Severity", str(case_info.get("severity", "N/A")).upper()],
        ["Created", case_info.get("created_at", "N/A")],
    ]
    inv = report_data.get("investigator", {})
    case_table_data.append(["Investigator", inv.get("name", inv.get("username", "N/A"))])
    case_table_data.append(["Generated", report_data.get("generated_at", "N/A")])

    table = Table(case_table_data, colWidths=[2 * inch, 4 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 16))

    # Analysis Summary
    elements.append(Paragraph("Analysis Summary", styles["Heading2"]))
    summary = report_data.get("analysis_summary", {})
    summary_data = [
        ["Metric", "Value"],
        ["Total Records Analyzed", str(summary.get("total_records_analyzed", 0))],
        ["Suspicious Records", str(summary.get("total_suspicious", 0))],
        ["Anomalies Detected", str(summary.get("total_anomalies", 0))],
        ["Threats Detected", str(summary.get("total_threats", 0))],
        ["Evidence Items", str(summary.get("total_evidence", 0))],
        ["Correlated Incidents", str(summary.get("total_incidents", 0))],
    ]
    table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 16))

    # Threat Classifications
    threat_dist = report_data.get("threat_classifications", {})
    if threat_dist:
        elements.append(Paragraph("Threat Classifications", styles["Heading2"]))
        threat_data = [["Threat Type", "Count"]]
        for k, v in sorted(threat_dist.items(), key=lambda x: -x[1]):
            threat_data.append([k, str(v)])
        table = Table(threat_data, colWidths=[4 * inch, 2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 16))

    # Incidents
    incidents = report_data.get("incidents", [])
    if incidents:
        elements.append(Paragraph("Correlated Incidents", styles["Heading2"]))
        for inc in incidents[:10]:
            elements.append(Paragraph(
                f"<b>{inc['name']}</b> — Severity: {str(inc.get('severity', 'N/A')).upper()}, "
                f"Events: {inc.get('event_count', 0)}, Risk: {inc.get('risk_score', 0):.1f}",
                styles["Normal"],
            ))
        elements.append(Spacer(1, 16))

    # Evidence Hashes
    evidence_list = report_data.get("evidence_list", [])
    if evidence_list:
        elements.append(Paragraph("Evidence Integrity Records", styles["Heading2"]))
        ev_data = [["Evidence ID", "Type", "Severity", "SHA-256 Hash"]]
        for e in evidence_list[:20]:
            ev_data.append([
                str(e["id"])[:12] + "...",
                e.get("type", "N/A"),
                str(e.get("severity", "N/A")).upper(),
                str(e.get("hash", "N/A"))[:24] + "..." if e.get("hash") else "N/A",
            ])
        table = Table(ev_data, colWidths=[1.5 * inch, 1 * inch, 1 * inch, 2.5 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 16))

    # Conclusions
    elements.append(Paragraph("Conclusions", styles["Heading2"]))
    for conclusion in report_data.get("conclusions", []):
        elements.append(Paragraph(f"• {conclusion}", styles["Normal"]))
        elements.append(Spacer(1, 6))

    # Disclaimer
    elements.append(Spacer(1, 24))
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.grey,
    )
    elements.append(Paragraph(
        "DISCLAIMER: This report was generated by an academic prototype system. "
        "It does not constitute legal evidence and should not be used to establish "
        "guilt or definitive attacker attribution. All results require human review.",
        disclaimer_style,
    ))

    doc.build(elements)


def _generate_csv(report_data: Dict[str, Any], file_path: Path):
    """Generate a CSV export of evidence records."""
    import csv

    evidence_list = report_data.get("evidence_list", [])
    if not evidence_list:
        evidence_list = [{"message": "No evidence data available"}]

    with open(file_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=evidence_list[0].keys())
        writer.writeheader()
        writer.writerows(evidence_list)
