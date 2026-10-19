"""
ML Model Evaluation Module.

Provides comprehensive evaluation metrics and reporting for trained models.
Generates confusion matrices, per-class reports, and feature importance analysis.

All metrics come from actual model execution — never fabricated.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)


def evaluate_classifier(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    class_names: Optional[List[str]] = None,
    model_name: str = "Model",
) -> Dict[str, Any]:
    """
    Compute comprehensive evaluation metrics for a classifier.
    
    Returns dict with:
    - accuracy, precision, recall, f1 (weighted)
    - per_class_report (dict from classification_report)
    - confusion_matrix
    - roc_auc (if probabilities provided)
    """
    metrics: Dict[str, Any] = {
        "model_name": model_name,
        "total_samples": int(len(y_true)),
    }

    # Basic metrics
    metrics["accuracy"] = round(float(accuracy_score(y_true, y_pred)), 4)
    metrics["precision_weighted"] = round(
        float(precision_score(y_true, y_pred, average="weighted", zero_division=0)), 4
    )
    metrics["recall_weighted"] = round(
        float(recall_score(y_true, y_pred, average="weighted", zero_division=0)), 4
    )
    metrics["f1_weighted"] = round(
        float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4
    )

    # Macro averages
    metrics["precision_macro"] = round(
        float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4
    )
    metrics["recall_macro"] = round(
        float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4
    )
    metrics["f1_macro"] = round(
        float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4
    )

    # Per-class report
    target_names = class_names if class_names else None
    report = classification_report(
        y_true, y_pred, target_names=target_names, zero_division=0, output_dict=True
    )
    metrics["classification_report"] = report

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics["confusion_matrix"] = cm.tolist()

    # ROC-AUC (for binary or multi-class with probabilities)
    if y_proba is not None:
        try:
            if y_proba.shape[1] == 2:
                # Binary
                metrics["roc_auc"] = round(
                    float(roc_auc_score(y_true, y_proba[:, 1])), 4
                )
            else:
                # Multi-class OvR
                metrics["roc_auc_ovr"] = round(
                    float(roc_auc_score(y_true, y_proba, multi_class="ovr")), 4
                )
        except ValueError as e:
            logger.warning(f"Could not compute ROC-AUC: {e}")

    logger.info(f"Evaluation for {model_name}:")
    logger.info(f"  Accuracy:  {metrics['accuracy']}")
    logger.info(f"  F1 (weighted): {metrics['f1_weighted']}")
    logger.info(f"  F1 (macro):    {metrics['f1_macro']}")

    return metrics


def evaluate_anomaly_detector(
    y_true_binary: np.ndarray,
    anomaly_predictions: np.ndarray,
    anomaly_scores: np.ndarray,
    model_name: str = "Isolation Forest",
) -> Dict[str, Any]:
    """
    Evaluate anomaly detection using binary labels.
    
    y_true_binary: 1 = attack/anomaly, 0 = benign/normal
    anomaly_predictions: 1 = normal, -1 = anomaly (from IF)
    anomaly_scores: score_samples output (more negative = more anomalous)
    """
    # Convert IF predictions to binary: anomaly=1, normal=0
    pred_binary = (anomaly_predictions == -1).astype(int)

    metrics: Dict[str, Any] = {
        "model_name": model_name,
        "total_samples": int(len(y_true_binary)),
        "anomalies_detected": int(pred_binary.sum()),
        "actual_anomalies": int(y_true_binary.sum()),
    }

    metrics["precision"] = round(
        float(precision_score(y_true_binary, pred_binary, zero_division=0)), 4
    )
    metrics["recall"] = round(
        float(recall_score(y_true_binary, pred_binary, zero_division=0)), 4
    )
    metrics["f1_score"] = round(
        float(f1_score(y_true_binary, pred_binary, zero_division=0)), 4
    )

    # ROC-AUC using anomaly scores
    try:
        # Negate scores because more negative = more anomalous
        metrics["roc_auc"] = round(
            float(roc_auc_score(y_true_binary, -anomaly_scores)), 4
        )
    except ValueError:
        logger.warning("Could not compute ROC-AUC for anomaly detector")

    # Confusion matrix
    cm = confusion_matrix(y_true_binary, pred_binary)
    metrics["confusion_matrix"] = cm.tolist()

    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics["true_positives"] = int(tp)
        metrics["true_negatives"] = int(tn)
        metrics["false_positives"] = int(fp)
        metrics["false_negatives"] = int(fn)
        metrics["false_positive_rate"] = round(float(fp / max(fp + tn, 1)), 4)
        metrics["false_negative_rate"] = round(float(fn / max(fn + tp, 1)), 4)

    return metrics


def save_evaluation_report(
    metrics: Dict[str, Any],
    output_path: Path,
) -> None:
    """Save evaluation metrics to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    logger.info(f"Evaluation report saved to {output_path}")
