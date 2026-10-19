"""
Random Forest Training.

Purpose: Supervised threat classification — classify known attack/traffic categories.
Concept: "What known threat/traffic category does this resemble?"

Uses actual labels from CICIDS2017 dataset. Does NOT invent attack categories.
Uses class_weight='balanced' to handle dataset imbalance.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from ml.training.config import RF_PARAMS, MODELS_DIR, RF_MODEL_FILE, TEST_SIZE, RANDOM_STATE

logger = logging.getLogger(__name__)


def train_random_forest(
    X: np.ndarray,
    y: np.ndarray,
    preprocessor,
) -> Dict[str, Any]:
    """
    Train Random Forest for threat classification.
    
    Uses train/test split to avoid data leakage in evaluation.
    
    Returns:
        Dictionary of evaluation metrics (all from actual model execution).
    """
    start = time.time()

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # Train Random Forest
    logger.info(f"Training Random Forest with params: {RF_PARAMS}")
    model = RandomForestClassifier(**RF_PARAMS)
    model.fit(X_train, y_train)

    train_time = time.time() - start
    logger.info(f"Random Forest training time: {train_time:.2f}s")

    # Predict
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # Classification report
    class_names = preprocessor.label_encoder.classes_.tolist()
    report = classification_report(
        y_test, y_pred, target_names=class_names, zero_division=0, output_dict=True
    )

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    # Feature importance
    feature_importance = {
        col: round(float(imp), 6)
        for col, imp in zip(
            preprocessor.feature_columns,
            model.feature_importances_,
        )
    }
    # Sort by importance
    feature_importance = dict(
        sorted(feature_importance.items(), key=lambda x: -x[1])
    )

    logger.info(f"Random Forest Evaluation:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  F1-Score:  {f1:.4f}")
    logger.info(f"\nClassification Report:")
    logger.info(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))
    logger.info(f"\nTop 10 Feature Importances:")
    for feat, imp in list(feature_importance.items())[:10]:
        logger.info(f"  {feat}: {imp:.6f}")

    metrics = {
        "algorithm": "Random Forest",
        "train_time_seconds": round(train_time, 2),
        "total_samples": int(len(X)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "feature_importance": feature_importance,
        "class_names": class_names,
        "parameters": RF_PARAMS,
    }

    # Inference throughput
    infer_start = time.time()
    _ = model.predict(X_test[:1000])
    infer_time = time.time() - infer_start
    metrics["inference_time_1000_samples"] = round(infer_time, 4)
    metrics["records_per_second"] = round(1000 / max(infer_time, 0.001), 1)

    # Save model
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / RF_MODEL_FILE
    joblib.dump(model, model_path)
    logger.info(f"Random Forest saved to {model_path}")

    return metrics
