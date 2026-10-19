"""
Train ML models on synthetic demo data.

Generates synthetic network flow data, trains both Isolation Forest and
Random Forest models, and saves all artifacts to ml/models/.

This allows the project to work WITHOUT downloading the full CICIDS2017 dataset.

Usage:
    cd Digital Forensics
    python -m scripts.train_on_demo
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
import joblib

from ml.demo.generate_demo_data import generate_demo_data
from ml.preprocessing.pipeline import DataPreprocessor
from ml.training.config import (
    FEATURE_COLUMNS,
    IF_MODEL_FILE,
    IF_PARAMS,
    MODELS_DIR,
    RF_MODEL_FILE,
    RF_PARAMS,
    TEST_SIZE,
    RANDOM_STATE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def main():
    logger.info("=" * 60)
    logger.info("AI-Driven Digital Forensics — Demo Model Training")
    logger.info("=" * 60)

    # ---- Step 1: Generate synthetic data ----
    logger.info("\n--- Step 1: Generating synthetic demo data ---")
    n_records = 10000  # More records for better model quality
    df = generate_demo_data(n_records)
    logger.info(f"Generated {len(df)} records")

    # ---- Step 2: Preprocess ----
    logger.info("\n--- Step 2: Preprocessing ---")
    preprocessor = DataPreprocessor()
    X, y, metadata = preprocessor.fit_transform(df)
    logger.info(f"Features shape: {X.shape}")
    logger.info(f"Label distribution: {preprocessor.get_class_distribution(y)}")

    # ---- Step 3: Train/test split ----
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    logger.info(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

    # ---- Step 4: Train Isolation Forest ----
    logger.info("\n--- Step 3: Training Isolation Forest ---")
    start = time.time()
    if_model = IsolationForest(**IF_PARAMS)
    if_model.fit(X_train)
    if_time = round(time.time() - start, 2)

    # Evaluate IF
    if_preds = if_model.predict(X_test)
    if_scores = if_model.score_samples(X_test)
    anomaly_count = int((if_preds == -1).sum())
    logger.info(f"Isolation Forest trained in {if_time}s")
    logger.info(f"Anomalies detected in test set: {anomaly_count}/{len(X_test)} "
                f"({anomaly_count/len(X_test)*100:.1f}%)")

    # ---- Step 5: Train Random Forest ----
    logger.info("\n--- Step 4: Training Random Forest ---")
    start = time.time()
    rf_model = RandomForestClassifier(**RF_PARAMS)
    rf_model.fit(X_train, y_train)
    rf_time = round(time.time() - start, 2)

    # Evaluate RF
    rf_preds = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, rf_preds)
    f1_weighted = f1_score(y_test, rf_preds, average="weighted", zero_division=0)
    precision = precision_score(y_test, rf_preds, average="weighted", zero_division=0)
    recall = recall_score(y_test, rf_preds, average="weighted", zero_division=0)

    logger.info(f"Random Forest trained in {rf_time}s")
    logger.info(f"Accuracy:  {accuracy:.4f}")
    logger.info(f"F1 Score:  {f1_weighted:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall:    {recall:.4f}")

    # Detailed classification report
    class_names = preprocessor.label_encoder.classes_
    report = classification_report(
        y_test, rf_preds,
        target_names=class_names,
        zero_division=0,
    )
    logger.info(f"\nClassification Report:\n{report}")

    # Feature importance
    importances = rf_model.feature_importances_
    feat_cols = preprocessor.feature_columns
    importance_pairs = sorted(
        zip(feat_cols, importances), key=lambda x: x[1], reverse=True
    )
    logger.info("\nTop 10 Most Important Features:")
    for feat, imp in importance_pairs[:10]:
        logger.info(f"  {feat.strip():40s} {imp:.4f}")

    # ---- Step 6: Save models ----
    logger.info("\n--- Step 5: Saving models ---")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(if_model, MODELS_DIR / IF_MODEL_FILE)
    logger.info(f"Saved: {MODELS_DIR / IF_MODEL_FILE}")

    joblib.dump(rf_model, MODELS_DIR / RF_MODEL_FILE)
    logger.info(f"Saved: {MODELS_DIR / RF_MODEL_FILE}")

    # Save preprocessing artifacts
    preprocessor.save(MODELS_DIR)

    # Save metrics as JSON
    metrics = {
        "dataset": "synthetic_demo",
        "n_records": n_records,
        "n_features": X.shape[1],
        "train_size": X_train.shape[0],
        "test_size": X_test.shape[0],
        "isolation_forest": {
            "training_time_s": if_time,
            "anomaly_count_test": anomaly_count,
            "anomaly_rate_test": round(anomaly_count / len(X_test), 4),
            "parameters": IF_PARAMS,
        },
        "random_forest": {
            "training_time_s": rf_time,
            "accuracy": round(accuracy, 4),
            "f1_weighted": round(f1_weighted, 4),
            "precision_weighted": round(precision, 4),
            "recall_weighted": round(recall, 4),
            "class_names": class_names.tolist(),
            "parameters": {k: str(v) for k, v in RF_PARAMS.items()},
        },
        "feature_importance": {
            feat.strip(): round(float(imp), 6)
            for feat, imp in importance_pairs
        },
    }

    with open(MODELS_DIR / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Saved: {MODELS_DIR / 'training_metrics.json'}")

    logger.info("\n" + "=" * 60)
    logger.info("All models trained and saved successfully!")
    logger.info(f"Models directory: {MODELS_DIR}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
