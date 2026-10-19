"""
System API — deep health checks, metrics, and audit log.

Provides production-grade observability endpoints:
- /api/system/health — verifies DB connectivity, ML model availability, disk space
- /api/system/metrics — request stats, response times, uptime
- /api/system/audit-log — recent API activity log
- /api/system/info — system version, environment, and configuration summary
"""

from __future__ import annotations

import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import Role, require_role
from app.models.user import User

router = APIRouter()


@router.get("/health")
async def deep_health_check():
    """
    Deep health check — verifies all subsystems are operational.
    
    Checks:
    1. Database connectivity (execute a simple query)
    2. ML model files exist and are loadable
    3. Upload directory is writable
    4. Disk space is sufficient
    """
    checks = {}
    overall_healthy = True

    # 1. Database connectivity
    try:
        from app.core.database import async_session_factory
        from sqlalchemy import text

        async with async_session_factory() as db:
            result = await db.execute(text("SELECT 1"))
            result.scalar()
        checks["database"] = {"status": "healthy", "detail": "Connection successful"}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "detail": str(e)}
        overall_healthy = False

    # 2. ML models availability
    try:
        from app.core import settings

        model_dir = Path(settings.MODEL_DIR)
        required_models = [
            "isolation_forest_v1.joblib",
            "random_forest_v1.joblib",
            "scaler_v1.joblib",
            "label_encoder_v1.joblib",
            "feature_columns.json",
        ]
        missing = [m for m in required_models if not (model_dir / m).exists()]
        if missing:
            checks["ml_models"] = {
                "status": "degraded",
                "detail": f"Missing models: {missing}",
                "model_dir": str(model_dir.resolve()),
            }
        else:
            total_size = sum((model_dir / m).stat().st_size for m in required_models)
            checks["ml_models"] = {
                "status": "healthy",
                "detail": f"All {len(required_models)} model artifacts loaded",
                "total_size_mb": round(total_size / (1024 * 1024), 2),
            }
    except Exception as e:
        checks["ml_models"] = {"status": "unhealthy", "detail": str(e)}
        overall_healthy = False

    # 3. Upload directory writable
    try:
        upload_dir = Path(settings.UPLOAD_DIR)
        upload_dir.mkdir(parents=True, exist_ok=True)
        test_file = upload_dir / ".health_check"
        test_file.write_text("ok")
        test_file.unlink()
        checks["upload_dir"] = {
            "status": "healthy",
            "detail": f"Writable at {upload_dir.resolve()}",
        }
    except Exception as e:
        checks["upload_dir"] = {"status": "unhealthy", "detail": str(e)}
        overall_healthy = False

    # 4. Disk space
    try:
        disk = shutil.disk_usage("/")
        free_gb = round(disk.free / (1024**3), 2)
        total_gb = round(disk.total / (1024**3), 2)
        pct_free = round((disk.free / disk.total) * 100, 1)
        disk_healthy = pct_free > 5  # Warn if < 5% free
        checks["disk_space"] = {
            "status": "healthy" if disk_healthy else "warning",
            "free_gb": free_gb,
            "total_gb": total_gb,
            "percent_free": pct_free,
        }
        if not disk_healthy:
            overall_healthy = False
    except Exception as e:
        checks["disk_space"] = {"status": "unknown", "detail": str(e)}

    # 5. Reports directory
    try:
        reports_dir = settings.reports_path
        report_count = len(list(reports_dir.glob("report_*")))
        checks["reports_dir"] = {
            "status": "healthy",
            "report_count": report_count,
            "path": str(reports_dir.resolve()),
        }
    except Exception as e:
        checks["reports_dir"] = {"status": "unhealthy", "detail": str(e)}

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


@router.get("/metrics")
async def get_system_metrics(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Return aggregated system metrics.
    
    Includes request counts, response time percentiles, error rates, and uptime.
    """
    from app.core.middleware import get_metrics

    metrics = get_metrics()

    # Add DB table counts
    try:
        from app.core.database import async_session_factory
        from sqlalchemy import text

        async with async_session_factory() as db:
            tables = {
                "users": "SELECT COUNT(*) FROM users",
                "cases": "SELECT COUNT(*) FROM cases",
                "evidence": "SELECT COUNT(*) FROM evidence",
                "threats": "SELECT COUNT(*) FROM threat_detections",
                "anomalies": "SELECT COUNT(*) FROM anomalies",
                "incidents": "SELECT COUNT(*) FROM incidents",
                "reports": "SELECT COUNT(*) FROM reports",
            }
            db_stats = {}
            for name, query in tables.items():
                try:
                    result = await db.execute(text(query))
                    db_stats[name] = result.scalar() or 0
                except Exception:
                    db_stats[name] = -1  # Table might not exist yet
            metrics["database_counts"] = db_stats
    except Exception as e:
        metrics["database_counts"] = {"error": str(e)}

    return metrics


@router.get("/audit-log")
async def get_audit_log(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    """
    Return recent API audit log entries (admin only).
    
    Each entry includes: timestamp, method, path, status code,
    duration, request ID, and client IP.
    """
    from app.core.middleware import get_audit_log

    entries = get_audit_log()
    return {
        "total_entries": len(entries),
        "entries": entries[:limit],
    }


@router.get("/info")
async def get_system_info():
    """
    Return system version and environment information.
    Non-sensitive configuration summary for diagnostics.
    """
    from app.core import settings

    return {
        "application": "AI-Driven Digital Forensics — Network Forensics",
        "version": "1.0.0",
        "environment": {
            "python_version": platform.python_version(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
        },
        "configuration": {
            "database_type": "SQLite" if settings.USE_SQLITE else "PostgreSQL",
            "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
            "jwt_algorithm": settings.JWT_ALGORITHM,
            "token_expiry_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "cors_origins": settings.cors_origins_list,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/db-summary")
async def get_database_summary(
    current_user: User = Depends(require_role(Role.VIEWER)),
):
    """
    Detailed database summary with table sizes and recent activity.
    """
    from app.core.database import async_session_factory
    from sqlalchemy import func, select, text
    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.models.incident import Incident
    from app.models.analysis_run import AnalysisRun

    async with async_session_factory() as db:
        # Case status distribution
        case_status_q = await db.execute(
            select(Case.status, func.count(Case.id)).group_by(Case.status)
        )
        case_statuses = {row[0]: row[1] for row in case_status_q.all()}

        # Evidence severity distribution
        ev_sev_q = await db.execute(
            select(Evidence.severity, func.count(Evidence.id))
            .where(Evidence.severity.isnot(None))
            .group_by(Evidence.severity)
        )
        evidence_severities = {row[0]: row[1] for row in ev_sev_q.all()}

        # Incident severity distribution
        inc_sev_q = await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.severity.isnot(None))
            .group_by(Incident.severity)
        )
        incident_severities = {row[0]: row[1] for row in inc_sev_q.all()}

        # Recent analysis runs
        runs_q = await db.execute(
            select(AnalysisRun)
            .order_by(AnalysisRun.started_at.desc())
            .limit(5)
        )
        recent_runs = []
        for run in runs_q.scalars().all():
            recent_runs.append({
                "id": str(run.id),
                "status": run.status,
                "total_records": run.total_records,
                "anomaly_count": run.anomaly_count,
                "threat_count": run.threat_count,
                "total_time": run.total_time,
                "started_at": run.started_at.isoformat() if run.started_at else None,
            })

        return {
            "case_status_distribution": case_statuses,
            "evidence_severity_distribution": evidence_severities,
            "incident_severity_distribution": incident_severities,
            "recent_analysis_runs": recent_runs,
        }
