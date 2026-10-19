"""
ML Inference Predictor.

Loads trained models and preprocessing artifacts.
Runs both Isolation Forest (anomaly) and Random Forest (classification) on new data.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from ml.preprocessing.pipeline import DataPreprocessor
from ml.training.config import (
    IF_MODEL_FILE,
    RF_MODEL_FILE,
    MODELS_DIR,
)

logger = logging.getLogger(__name__)


class ForensicsPredictor:
    """
    Loads trained models and runs inference on new network data.
    
    Models are loaded once and reused — never retrained on upload.
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or MODELS_DIR
        self.isolation_forest = None
        self.random_forest = None
        self.preprocessor: Optional[DataPreprocessor] = None
        self._loaded = False

    def load(self):
        """Load all models and preprocessing artifacts."""
        logger.info(f"Loading models from {self.model_dir}")

        # Load preprocessing pipeline
        self.preprocessor = DataPreprocessor.load(self.model_dir)

        # Load Isolation Forest
        if_path = self.model_dir / IF_MODEL_FILE
        if if_path.exists():
            self.isolation_forest = joblib.load(if_path)
            logger.info("Isolation Forest loaded")
        else:
            logger.warning(f"Isolation Forest model not found at {if_path}")

        # Load Random Forest
        rf_path = self.model_dir / RF_MODEL_FILE
        if rf_path.exists():
            self.random_forest = joblib.load(rf_path)
            logger.info("Random Forest loaded")
        else:
            logger.warning(f"Random Forest model not found at {rf_path}")

        self._loaded = True

    def predict(
        self, df: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Run full inference pipeline on a dataframe.
        
        Returns dict with:
            - anomaly_predictions: array of -1/1
            - anomaly_scores: array of float scores
            - threat_predictions: array of class labels
            - threat_probabilities: array of class probabilities
            - metadata: DataFrame of IP/port/protocol info
            - timing: dict of timing measurements
        """
        if not self._loaded:
            self.load()

        timing = {}
        results = {}

        # Preprocess
        start = time.time()
        X, metadata = self.preprocessor.transform(df)
        timing["preprocessing_seconds"] = round(time.time() - start, 4)

        results["total_records"] = len(X)
        results["metadata"] = metadata

        # Isolation Forest
        if self.isolation_forest is not None:
            start = time.time()
            anomaly_preds = self.isolation_forest.predict(X)
            anomaly_scores = self.isolation_forest.score_samples(X)
            timing["isolation_forest_seconds"] = round(time.time() - start, 4)

            results["anomaly_predictions"] = anomaly_preds  # 1=normal, -1=anomaly
            results["anomaly_scores"] = anomaly_scores
            results["anomaly_count"] = int((anomaly_preds == -1).sum())
        else:
            results["anomaly_predictions"] = np.ones(len(X))
            results["anomaly_scores"] = np.zeros(len(X))
            results["anomaly_count"] = 0

        # Random Forest
        if self.random_forest is not None:
            start = time.time()
            threat_pred_encoded = self.random_forest.predict(X)
            threat_proba = self.random_forest.predict_proba(X)
            timing["random_forest_seconds"] = round(time.time() - start, 4)

            # Decode labels
            threat_labels = self.preprocessor.label_encoder.inverse_transform(
                threat_pred_encoded
            )
            results["threat_predictions"] = threat_labels
            results["threat_probabilities"] = threat_proba
            results["threat_classes"] = self.preprocessor.label_encoder.classes_.tolist()

            # Count non-benign threats
            threat_count = sum(
                1 for label in threat_labels
                if label.strip().upper() != "BENIGN"
            )
            results["threat_count"] = threat_count
        else:
            results["threat_predictions"] = np.array(["UNKNOWN"] * len(X))
            results["threat_probabilities"] = np.zeros((len(X), 1))
            results["threat_classes"] = ["UNKNOWN"]
            results["threat_count"] = 0

        timing["total_inference_seconds"] = round(
            sum(v for v in timing.values()), 4
        )
        timing["records_per_second"] = round(
            len(X) / max(timing["total_inference_seconds"], 0.001), 1
        )
        results["timing"] = timing

        logger.info(
            f"Inference complete: {len(X)} records, "
            f"{results['anomaly_count']} anomalies, "
            f"{results.get('threat_count', 0)} threats, "
            f"{timing['total_inference_seconds']:.2f}s"
        )

        return results
