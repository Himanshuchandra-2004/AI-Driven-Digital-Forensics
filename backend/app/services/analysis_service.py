"""
Analysis Service — runs the full ML analysis pipeline as a background task.

Pipeline:
1. Load uploaded data
2. Preprocess & extract features
3. Run Isolation Forest (anomaly detection)
4. Run Random Forest (threat classification)
5. Create network events, anomalies, threat detections
6. Extract evidence from suspicious events
7. Correlate related evidence into incidents
8. Calculate risk scores
9. Generate evidence hashes
10. Create chain of custody records
"""

from __future__ import annotations

import logging
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Add project root to path for ML imports
_project_root = str(Path(__file__).parent.parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


async def run_full_analysis(
    analysis_run_id: str,
    case_id: str,
    filename: str,
    user_id: str,
):
    """
    Run the complete analysis pipeline in the background.
    
    This function creates its own database session since it runs
    outside the request lifecycle.
    """
    from app.core.database import async_session_factory
    from app.models.analysis_run import AnalysisRun
    from app.models.case import Case
    from app.models.network_event import NetworkEvent
    from app.models.anomaly import Anomaly
    from app.models.threat_detection import ThreatDetection
    from app.models.evidence import Evidence
    from app.models.chain_of_custody import ChainOfCustody
    from app.models.incident import Incident
    from app.models.evidence_relation import EvidenceRelation
    from app.services.hash_service import compute_evidence_hash, get_evidence_canonical_data
    from app.services.risk_service import (
        calculate_risk_score,
        classify_severity,
        normalize_anomaly_score,
    )
    from app.core import settings

    async with async_session_factory() as db:
        try:
            # Get analysis run
            result = await db.execute(
                select(AnalysisRun).where(AnalysisRun.id == analysis_run_id)
            )
            run = result.scalar_one()
            run.status = "processing"
            run.started_at = datetime.now(timezone.utc)
            await db.commit()

            total_start = time.time()

            # ---- Step 1: Load data ----
            upload_path = Path(settings.UPLOAD_DIR) / filename if filename else None
            if upload_path and upload_path.exists():
                df = pd.read_csv(upload_path, low_memory=False)
            else:
                logger.error(f"File not found: {upload_path}")
                run.status = "failed"
                run.error_message = f"Upload file not found: {filename}"
                await db.commit()
                return

            # ---- Step 2: Run ML inference ----
            from ml.inference.predictor import ForensicsPredictor

            predictor = ForensicsPredictor(Path(settings.MODEL_DIR))
            predictor.load()
            ml_results = predictor.predict(df)

            run.total_records = ml_results["total_records"]
            run.preprocessing_time = ml_results["timing"].get("preprocessing_seconds")
            run.inference_time = ml_results["timing"].get("total_inference_seconds")

            # ---- Step 3: Create network events and detections ----
            metadata = ml_results["metadata"]
            anomaly_preds = ml_results["anomaly_predictions"]
            anomaly_scores = ml_results["anomaly_scores"]
            threat_preds = ml_results["threat_predictions"]
            threat_proba = ml_results["threat_probabilities"]
            threat_classes = ml_results.get("threat_classes", [])

            evidence_list = []
            previous_hash = None
            suspicious_count = 0
            anomaly_count = 0
            threat_count = 0

            # Process each record
            batch_size = min(len(anomaly_preds), ml_results["total_records"])
            for i in range(batch_size):
                # Extract metadata
                src_ip = _safe_get(metadata, i, "Source IP", " Source IP")
                dst_ip = _safe_get(metadata, i, "Destination IP", " Destination IP")
                src_port = _safe_int(_safe_get(metadata, i, "Source Port", " Source Port"))
                dst_port = _safe_int(_safe_get(metadata, i, "Destination Port", " Destination Port"))
                protocol = str(_safe_get(metadata, i, "Protocol", " Protocol") or "")

                # Create network event
                event = NetworkEvent(
                    analysis_run_id=uuid.UUID(analysis_run_id),
                    case_id=uuid.UUID(case_id),
                    src_ip=str(src_ip) if src_ip else None,
                    dst_ip=str(dst_ip) if dst_ip else None,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    row_index=i,
                    event_timestamp=datetime.now(timezone.utc),
                )
                db.add(event)
                await db.flush()

                # Anomaly detection result
                is_anomaly = bool(anomaly_preds[i] == -1)
                a_score = float(anomaly_scores[i])
                risk_score_val = normalize_anomaly_score(a_score)

                anomaly_record = Anomaly(
                    network_event_id=event.id,
                    analysis_run_id=uuid.UUID(analysis_run_id),
                    case_id=uuid.UUID(case_id),
                    anomaly_score=a_score,
                    risk_score=risk_score_val,
                    is_anomaly=is_anomaly,
                    severity=classify_severity(risk_score_val) if is_anomaly else "low",
                )
                db.add(anomaly_record)

                if is_anomaly:
                    anomaly_count += 1

                # Threat classification result
                predicted_class = str(threat_preds[i]).strip()
                confidence = 0.0
                class_probs = {}
                if len(threat_proba) > i:
                    max_prob_idx = np.argmax(threat_proba[i])
                    confidence = float(threat_proba[i][max_prob_idx])
                    if threat_classes:
                        class_probs = {
                            cls: round(float(threat_proba[i][j]), 4)
                            for j, cls in enumerate(threat_classes)
                            if j < len(threat_proba[i])
                        }

                is_threat = predicted_class.upper() != "BENIGN"

                threat_sev = "low"
                if is_threat:
                    threat_risk = calculate_risk_score(
                        anomaly_score=a_score if is_anomaly else None,
                        threat_confidence=confidence,
                        threat_class=predicted_class,
                    )
                    threat_sev = classify_severity(threat_risk)

                threat_record = ThreatDetection(
                    network_event_id=event.id,
                    analysis_run_id=uuid.UUID(analysis_run_id),
                    case_id=uuid.UUID(case_id),
                    predicted_class=predicted_class,
                    confidence=confidence,
                    class_probabilities=class_probs,
                    severity=threat_sev,
                )
                db.add(threat_record)

                if is_threat:
                    threat_count += 1

                # ---- Step 4: Extract evidence from suspicious events ----
                if is_anomaly or is_threat:
                    suspicious_count += 1

                    evidence_risk = calculate_risk_score(
                        anomaly_score=a_score if is_anomaly else None,
                        threat_confidence=confidence if is_threat else None,
                        threat_class=predicted_class if is_threat else None,
                    )
                    evidence_severity = classify_severity(evidence_risk)

                    evidence_type = "combined" if (is_anomaly and is_threat) else (
                        "anomaly" if is_anomaly else "threat"
                    )

                    await db.flush()

                    evidence = Evidence(
                        case_id=uuid.UUID(case_id),
                        network_event_id=event.id,
                        threat_detection_id=threat_record.id if is_threat else None,
                        anomaly_id=anomaly_record.id if is_anomaly else None,
                        evidence_type=evidence_type,
                        predicted_threat=predicted_class if is_threat else None,
                        anomaly_score=a_score if is_anomaly else None,
                        classification_confidence=confidence if is_threat else None,
                        severity=evidence_severity,
                        risk_score=evidence_risk,
                        src_ip=str(src_ip) if src_ip else None,
                        dst_ip=str(dst_ip) if dst_ip else None,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        source_file=filename,
                    )
                    db.add(evidence)
                    await db.flush()

                    # Compute hash with chaining
                    canonical = get_evidence_canonical_data(evidence)
                    evidence.previous_hash = previous_hash
                    evidence.evidence_hash = compute_evidence_hash(canonical, previous_hash)
                    previous_hash = evidence.evidence_hash

                    # Chain of custody: collected
                    custody = ChainOfCustody(
                        evidence_id=evidence.id,
                        user_id=uuid.UUID(user_id),
                        action="collected",
                        description=f"Evidence auto-extracted from analysis. Type: {evidence_type}, Threat: {predicted_class}",
                        integrity_hash=evidence.evidence_hash,
                    )
                    db.add(custody)

                    evidence_list.append(evidence)

            # ---- Step 5: Evidence Correlation ----
            await _correlate_evidence(
                db, evidence_list, uuid.UUID(case_id), uuid.UUID(user_id)
            )

            # ---- Step 6: Update analysis run and case ----
            run.suspicious_records = suspicious_count
            run.anomaly_count = anomaly_count
            run.threat_count = threat_count
            run.total_time = round(time.time() - total_start, 2)
            run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)
            run.metrics = ml_results.get("timing", {})

            # Update case
            case_result = await db.execute(
                select(Case).where(Case.id == case_id)
            )
            case = case_result.scalar_one()
            case.status = "completed"
            case.evidence_count = len(evidence_list)
            case.threat_count = threat_count
            case.anomaly_count = anomaly_count

            # Set case severity to the highest evidence severity
            if evidence_list:
                severities = [e.severity for e in evidence_list if e.severity]
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if severities:
                    case.severity = max(severities, key=lambda s: sev_order.get(s, 0))

            await db.commit()

            logger.info(
                f"Analysis complete: {batch_size} records, "
                f"{anomaly_count} anomalies, {threat_count} threats, "
                f"{len(evidence_list)} evidence items, {run.total_time}s"
            )

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            run.status = "failed"
            run.error_message = str(e)
            run.completed_at = datetime.now(timezone.utc)
            await db.commit()


async def _correlate_evidence(
    db: AsyncSession,
    evidence_list: list,
    case_id: uuid.UUID,
    user_id: uuid.UUID,
):
    """
    Correlate related evidence into incidents.
    
    Strategy:
    1. Group by source IP
    2. Within groups, cluster by threat type
    3. Cross-correlate shared destination IPs
    4. Create incidents from clusters
    """
    from app.models.incident import Incident
    from app.models.evidence_relation import EvidenceRelation
    from app.services.risk_service import calculate_risk_score, classify_severity

    if not evidence_list:
        return

    # Group evidence by source IP
    ip_groups = {}
    for ev in evidence_list:
        key = ev.src_ip or "unknown"
        if key not in ip_groups:
            ip_groups[key] = []
        ip_groups[key].append(ev)

    incident_count = 0
    for src_ip, group in ip_groups.items():
        if len(group) < 2:
            continue  # Need at least 2 events to form an incident

        # Sub-group by threat type
        threat_groups = {}
        for ev in group:
            t_key = ev.predicted_threat or "anomaly"
            if t_key not in threat_groups:
                threat_groups[t_key] = []
            threat_groups[t_key].append(ev)

        for threat_type, sub_group in threat_groups.items():
            if len(sub_group) < 2:
                continue

            incident_count += 1

            # Collect incident metadata
            dst_ips = list(set(ev.dst_ip for ev in sub_group if ev.dst_ip))
            src_ips = list(set(ev.src_ip for ev in sub_group if ev.src_ip))
            categories = list(set(
                ev.predicted_threat for ev in sub_group
                if ev.predicted_threat and ev.predicted_threat.upper() != "BENIGN"
            ))

            # Calculate incident risk
            avg_risk = np.mean([ev.risk_score for ev in sub_group if ev.risk_score])
            incident_risk = calculate_risk_score(
                anomaly_score=None,
                threat_confidence=avg_risk / 100,
                threat_class=threat_type if threat_type != "anomaly" else None,
                frequency_count=len(sub_group),
                correlation_count=len(dst_ips),
            )

            incident = Incident(
                case_id=case_id,
                name=f"INC-{incident_count:03d}: {threat_type} from {src_ip}",
                description=(
                    f"Correlated {len(sub_group)} suspicious events from {src_ip} "
                    f"involving {threat_type} activity targeting {len(dst_ips)} destination(s)."
                ),
                severity=classify_severity(incident_risk),
                risk_score=incident_risk,
                event_count=len(sub_group),
                involved_ips={"sources": src_ips, "destinations": dst_ips},
                threat_categories=categories,
                first_seen=sub_group[0].extraction_timestamp,
                last_seen=sub_group[-1].extraction_timestamp,
            )
            db.add(incident)
            await db.flush()

            # Link evidence to incident
            for ev in sub_group:
                relation = EvidenceRelation(
                    evidence_id=ev.id,
                    incident_id=incident.id,
                    relation_type="ip_correlation",
                    correlation_score=1.0,
                )
                db.add(relation)

    # Cross-correlate: different sources targeting same destination
    dst_groups = {}
    for ev in evidence_list:
        key = ev.dst_ip or "unknown"
        if key not in dst_groups:
            dst_groups[key] = []
        dst_groups[key].append(ev)

    for dst_ip, group in dst_groups.items():
        src_ips_in_group = set(ev.src_ip for ev in group if ev.src_ip)
        if len(src_ips_in_group) >= 2 and len(group) >= 3:
            incident_count += 1
            categories = list(set(
                ev.predicted_threat for ev in group
                if ev.predicted_threat and ev.predicted_threat.upper() != "BENIGN"
            ))

            incident = Incident(
                case_id=case_id,
                name=f"INC-{incident_count:03d}: Multi-source attack on {dst_ip}",
                description=(
                    f"Multiple sources ({len(src_ips_in_group)}) targeting {dst_ip} "
                    f"with {len(group)} suspicious events."
                ),
                severity="high",
                risk_score=75.0,
                event_count=len(group),
                involved_ips={
                    "sources": list(src_ips_in_group),
                    "destinations": [dst_ip],
                },
                threat_categories=categories,
                first_seen=group[0].extraction_timestamp,
                last_seen=group[-1].extraction_timestamp,
            )
            db.add(incident)
            await db.flush()

            for ev in group:
                relation = EvidenceRelation(
                    evidence_id=ev.id,
                    incident_id=incident.id,
                    relation_type="target_correlation",
                    correlation_score=0.8,
                )
                db.add(relation)

    logger.info(f"Created {incident_count} incidents from {len(evidence_list)} evidence items")


def _safe_get(metadata, idx, *col_names):
    """Safely get a value from metadata DataFrame."""
    for col in col_names:
        if col in metadata.columns and idx < len(metadata):
            val = metadata.iloc[idx].get(col)
            if pd.notna(val):
                return val
    return None


def _safe_int(val):
    """Safely convert to int."""
    if val is None:
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None
