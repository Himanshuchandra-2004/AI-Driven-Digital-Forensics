"""
Isolation Forest Training.

Purpose: Anomaly detection — identify unusual network behaviour.
Concept: "Does this network activity look unusual compared with normal behaviour?"

Isolation Forest works by randomly selecting a feature and splitting data.
Anomalies are isolated in fewer splits (shorter path length).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)

from ml.training.config import IF_PARAMS, MODELS_DIR, IF_MODEL_FILE

logger = logging.getLogger(__name__)


def train_isolation_forest(
    X: np.ndarray,
    y: np.ndarray,
    preprocessor,
) -> Dict[str, Any]:
    """
    Train Isolation Forest for anomaly detection.
    
    Since IF is unsupervised, it doesn't use labels for training.
    Labels are used ONLY for evaluation (when ground truth exists).
    
    Returns:
        Dictionary of evaluation metrics.
    """
    start = time.time()

    # Train Isolation Forest (unsupervised — no labels used)
    logger.info(f"Training Isolation Forest with params: {IF_PARAMS}")
    model = IsolationForest(**IF_PARAMS)
    model.fit(X)

    train_time = time.time() - start
    logger.info(f"Isolation Forest training time: {train_time:.2f}s")

    # Get predictions
    # IF predict: 1 = normal, -1 = anomaly
    predictions = model.predict(X)
    scores = model.score_samples(X)

    # Convert IF predictions to binary: anomaly=1, normal=0
    if_anomaly = (predictions == -1).astype(int)

    # Create binary ground truth: BENIGN=0, attack=1
    label_classes = preprocessor.label_encoder.classes_
    benign_idx = None
    for i, cls in enumerate(label_classes):
        if cls.strip().upper() == "BENIGN":
            benign_idx = i
            break

    metrics = {
        "algorithm": "Isolation Forest",
        "train_time_seconds": round(train_time, 2),
        "total_samples": int(len(X)),
        "anomalies_detected": int(if_anomaly.sum()),
        "normal_detected": int((if_anomaly == 0).sum()),
        "anomaly_percentage": round(float(if_anomaly.mean() * 100), 2),
        "parameters": IF_PARAMS,
    }

    # Evaluate against ground truth if benign class exists
    if benign_idx is not None:
        y_true_binary = (y != benign_idx).astype(int)  # 1 = attack, 0 = benign

        # Metrics
        precision = precision_score(y_true_binary, if_anomaly, zero_division=0)
        recall = recall_score(y_true_binary, if_anomaly, zero_division=0)
        f1 = f1_score(y_true_binary, if_anomaly, zero_division=0)

        metrics.update({
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
        })

        # ROC-AUC using anomaly scores (more negative = more anomalous)
        try:
            roc_auc = roc_auc_score(y_true_binary, -scores)
            metrics["roc_auc"] = round(float(roc_auc), 4)
        except ValueError:
            logger.warning("Could not compute ROC-AUC (single class in batch)")

        # PR-AUC
        try:
            pr_auc = average_precision_score(y_true_binary, -scores)
            metrics["pr_auc"] = round(float(pr_auc), 4)
        except ValueError:
            logger.warning("Could not compute PR-AUC")

        logger.info(f"Isolation Forest Evaluation (against ground truth):")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall:    {recall:.4f}")
        logger.info(f"  F1-Score:  {f1:.4f}")
        if "roc_auc" in metrics:
            logger.info(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        if "pr_auc" in metrics:
            logger.info(f"  PR-AUC:    {metrics['pr_auc']:.4f}")
    else:
        logger.warning("No BENIGN class found — cannot evaluate IF against ground truth")

    # Inference throughput
    infer_start = time.time()
    _ = model.predict(X[:1000])
    infer_time = time.time() - infer_start
    metrics["inference_time_1000_samples"] = round(infer_time, 4)
    metrics["records_per_second"] = round(1000 / max(infer_time, 0.001), 1)

    # Save model
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / IF_MODEL_FILE
    joblib.dump(model, model_path)
    logger.info(f"Isolation Forest saved to {model_path}")

    return metrics
