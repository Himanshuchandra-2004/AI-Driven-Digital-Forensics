"""
Initialize the database and create a default admin user.

Usage:
    cd Digital Forensics
    python -m scripts.init_db
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


async def init():
    from app.core.database import create_all_tables, async_session_factory
    from app.core.security import hash_password
    from app.models.user import User
    from sqlalchemy import select

    # Create tables
    logger.info("Creating database tables...")
    await create_all_tables()
    logger.info("Tables created successfully!")

    # Create default admin user
    async with async_session_factory() as db:
        result = await db.execute(
            select(User).where(User.username == "admin")
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.info("Admin user already exists, skipping.")
        else:
            admin = User(
                username="admin",
                email="admin@forensics.local",
                password_hash=hash_password("admin123"),
                full_name="System Administrator",
                role="admin",
            )
            db.add(admin)

            # Also create a demo investigator
            investigator = User(
                username="investigator",
                email="investigator@forensics.local",
                password_hash=hash_password("invest123"),
                full_name="Demo Investigator",
                role="investigator",
            )
            db.add(investigator)

            await db.commit()
            logger.info("Created default users:")
            logger.info("  admin / admin123 (role: admin)")
            logger.info("  investigator / invest123 (role: investigator)")

        # Seed Model Versions from training_metrics.json if they don't exist
        from app.models.model_version import ModelVersion
        import json
        from pathlib import Path

        model_check = await db.execute(select(ModelVersion))
        if model_check.scalars().first():
            logger.info("Model versions already exist in DB, skipping.")
        else:
            metrics_path = Path(__file__).parent.parent / "ml" / "models" / "training_metrics.json"
            features_path = Path(__file__).parent.parent / "ml" / "models" / "feature_columns.json"
            
            if metrics_path.exists():
                logger.info(f"Loading training metrics from {metrics_path}...")
                with open(metrics_path, "r") as f:
                    metrics_data = json.load(f)
                
                features = []
                if features_path.exists():
                    with open(features_path, "r") as f:
                        features = json.load(f)
                else:
                    features = list(metrics_data.get("feature_importance", {}).keys())

                # 1. Isolation Forest
                if_metrics = metrics_data.get("isolation_forest", {})
                if_version = ModelVersion(
                    algorithm="Isolation Forest (Anomaly Detection)",
                    version="1.0",
                    dataset_name=metrics_data.get("dataset", "synthetic_demo"),
                    features=features,
                    metrics={
                        "train_time_seconds": if_metrics.get("training_time_s"),
                        "anomaly_count_test": if_metrics.get("anomaly_count_test"),
                        "anomaly_rate_test": if_metrics.get("anomaly_rate_test"),
                    },
                    parameters=if_metrics.get("parameters", {}),
                    model_path="ml/models/isolation_forest_v1.joblib",
                    status="active",
                )
                db.add(if_version)

                # 2. Random Forest
                rf_metrics = metrics_data.get("random_forest", {})
                rf_version = ModelVersion(
                    algorithm="Random Forest (Threat Classification)",
                    version="1.0",
                    dataset_name=metrics_data.get("dataset", "synthetic_demo"),
                    features=features,
                    metrics={
                        "accuracy": rf_metrics.get("accuracy"),
                        "f1_score": rf_metrics.get("f1_weighted"),
                        "precision": rf_metrics.get("precision_weighted"),
                        "recall": rf_metrics.get("recall_weighted"),
                        "train_time_seconds": rf_metrics.get("training_time_s"),
                        "feature_importance": metrics_data.get("feature_importance", {}),
                    },
                    parameters=rf_metrics.get("parameters", {}),
                    model_path="ml/models/random_forest_v1.joblib",
                    status="active",
                )
                db.add(rf_version)
                
                await db.commit()
                logger.info("Successfully seeded model versions in database!")
            else:
                logger.warning(f"training_metrics.json not found at {metrics_path}. Make sure models are trained first.")

    logger.info("Database initialization complete!")


def main():
    asyncio.run(init())


if __name__ == "__main__":
    main()
