"""
ML Training Entry Point.

Trains both Isolation Forest and Random Forest on CICIDS2017 data.

Usage:
    python -m ml.training.train

Workflow:
    1. Load raw CSV files from ml/data/raw/
    2. Preprocess and clean data
    3. Train Isolation Forest (anomaly detection)
    4. Train Random Forest (threat classification)
    5. Evaluate both models
    6. Save models and preprocessing artifacts
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml.preprocessing.pipeline import DataPreprocessor
from ml.training.train_isolation_forest import train_isolation_forest
from ml.training.train_random_forest import train_random_forest
from ml.training.config import (
    DATA_RAW_DIR,
    MODELS_DIR,
    MAX_TRAINING_SAMPLES,
    RANDOM_STATE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_dataset() -> pd.DataFrame:
    """Load and concatenate all CICIDS2017 CSV files from data/raw/."""
    csv_files = sorted(DATA_RAW_DIR.glob("*.csv"))
    if not csv_files:
        logger.error(
            f"No CSV files found in {DATA_RAW_DIR}. "
            "Download CICIDS2017 MachineLearningCSV.zip from "
            "https://www.unb.ca/cic/datasets/ids-2017.html "
            "and extract CSV files into ml/data/raw/"
        )
        sys.exit(1)

    logger.info(f"Found {len(csv_files)} CSV files:")
    dfs = []
    for f in csv_files:
        logger.info(f"  Loading: {f.name}")
        df = pd.read_csv(f, encoding="utf-8", low_memory=False)
        dfs.append(df)
        logger.info(f"    → {len(df)} rows, {len(df.columns)} columns")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total combined: {len(combined)} rows")
    return combined


def main():
    """Main training pipeline."""
    logger.info("=" * 60)
    logger.info("AI-Driven Digital Forensics — ML Training Pipeline")
    logger.info("=" * 60)

    start_time = time.time()

    # 1. Load dataset
    logger.info("\n[1/5] Loading dataset...")
    df = load_dataset()

    # 2. Sample if too large
    if len(df) > MAX_TRAINING_SAMPLES:
        logger.info(
            f"Dataset too large ({len(df)} rows). "
            f"Sampling {MAX_TRAINING_SAMPLES} rows for training."
        )
        df = df.sample(n=MAX_TRAINING_SAMPLES, random_state=RANDOM_STATE)

    # 3. Preprocess
    logger.info("\n[2/5] Preprocessing data...")
    preprocessor = DataPreprocessor()
    X, y, metadata = preprocessor.fit_transform(df)

    # Show class distribution
    class_dist = preprocessor.get_class_distribution(y)
    logger.info("Class distribution:")
    for cls, count in sorted(class_dist.items(), key=lambda x: -x[1]):
        pct = count / len(y) * 100
        logger.info(f"  {cls}: {count} ({pct:.1f}%)")

    # Check for imbalance
    max_count = max(class_dist.values())
    min_count = min(class_dist.values())
    if max_count / max(min_count, 1) > 10:
        logger.warning(
            "DATASET IS IMBALANCED. Largest class is >10x smallest. "
            "Random Forest uses class_weight='balanced' to compensate."
        )

    # 4. Train Isolation Forest
    logger.info("\n[3/5] Training Isolation Forest (anomaly detection)...")
    if_metrics = train_isolation_forest(X, y, preprocessor)

    # 5. Train Random Forest
    logger.info("\n[4/5] Training Random Forest (threat classification)...")
    rf_metrics = train_random_forest(X, y, preprocessor)

    # 6. Save preprocessing artifacts
    logger.info("\n[5/5] Saving preprocessing artifacts...")
    preprocessor.save()

    elapsed = time.time() - start_time
    logger.info("\n" + "=" * 60)
    logger.info("Training complete!")
    logger.info(f"Total time: {elapsed:.1f}s")
    logger.info(f"Models saved to: {MODELS_DIR}")
    logger.info("=" * 60)

    return if_metrics, rf_metrics


if __name__ == "__main__":
    main()
