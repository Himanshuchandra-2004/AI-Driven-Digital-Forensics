"""
Demo Service — creates a complete demo case with synthetic data.

When "Load Demo Case" is clicked:
1. Creates demo case
2. Generates synthetic network flow data
3. Saves to upload directory
4. Runs the full analysis pipeline
"""

from __future__ import annotations

import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_project_root = str(Path(__file__).parent.parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


async def create_demo_case(
    user_id: str,
    db: AsyncSession,
    n_records: int = 5000,
) -> dict:
    """
    Create a complete demo case with synthetic data.
    
    Generates demo data, saves it, and triggers analysis.
    Returns the created case and analysis run info.
    """
    from app.models.case import Case
    from app.models.analysis_run import AnalysisRun
    from app.core import settings

    # Create demo case
    case = Case(
        user_id=uuid.UUID(user_id),
        name="[DEMO] Network Forensics Analysis — Synthetic Data",
        description=(
            "This is a DEMO case created with synthetic network flow data. "
            "All data is artificially generated and clearly labeled as DEMO/SYNTHETIC. "
            f"Contains {n_records} synthetic network flow records including: "
            "normal traffic, DoS, DDoS, PortScan, Bot (C&C), Brute Force, and Web Attack patterns."
        ),
        status="analyzing",
    )
    db.add(case)
    await db.flush()
    await db.refresh(case)

    # Generate synthetic data
    from ml.demo.generate_demo_data import generate_demo_data

    demo_df = generate_demo_data(n_records)

    # Save to upload directory
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    demo_filename = f"demo_{uuid.uuid4()}.csv"
    demo_path = upload_dir / demo_filename
    demo_df.to_csv(demo_path, index=False)
    logger.info(f"Demo data saved to {demo_path}")

    # Create analysis run
    analysis_run = AnalysisRun(
        case_id=case.id,
        status="queued",
        source_file=demo_filename,
        source_type="csv",
    )
    db.add(analysis_run)
    await db.flush()
    await db.refresh(analysis_run)

    await db.commit()

    return {
        "case_id": str(case.id),
        "case_name": case.name,
        "analysis_run_id": str(analysis_run.id),
        "demo_filename": demo_filename,
        "records": n_records,
        "message": "Demo case created. Analysis will run in background.",
    }
