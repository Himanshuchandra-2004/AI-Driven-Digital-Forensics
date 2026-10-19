"""
Data Preprocessing Pipeline for CICIDS2017 network flow data.

Handles:
- Missing values (drop rows with NaN in feature columns)
- Infinite values (replace with NaN then drop)
- Duplicate records (remove)
- Invalid records (non-numeric values in numeric columns)
- Column name normalization (strip whitespace)
- Feature selection (only meaningful network-flow features)

The same preprocessing transformation is used for both TRAINING and INFERENCE.
Preprocessing artifacts (scaler, encoder) are saved and loaded, never retrained on upload.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

from ml.training.config import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    METADATA_COLUMNS,
    MODELS_DIR,
    SCALER_FILE,
    LABEL_ENCODER_FILE,
    FEATURE_COLUMNS_FILE,
)

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Reusable preprocessing pipeline.
    
    Usage:
        # Training
        preprocessor = DataPreprocessor()
        X_train, y_train, metadata = preprocessor.fit_transform(df)
        preprocessor.save()
        
        # Inference
        preprocessor = DataPreprocessor.load()
        X_new, metadata = preprocessor.transform(df)
    """

    def __init__(self):
        self.scaler: Optional[StandardScaler] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.feature_columns: List[str] = []
        self._fitted = False

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean raw dataframe:
        - Strip column name whitespace
        - Replace infinite values with NaN
        - Drop rows with NaN in feature columns
        - Remove duplicate rows
        - Convert feature columns to numeric
        """
        logger.info(f"Cleaning dataframe: {len(df)} rows, {len(df.columns)} columns")

        # Strip column name whitespace for matching
        # But CICIDS2017 has leading spaces in column names, so we need to handle both
        original_cols = df.columns.tolist()

        # Replace inf values
        df = df.replace([np.inf, -np.inf], np.nan)

        # Identify which feature columns exist in this dataframe
        available_features = []
        for col in FEATURE_COLUMNS:
            if col in df.columns:
                available_features.append(col)
            elif col.strip() in df.columns:
                available_features.append(col.strip())

        if not available_features:
            # Try stripping spaces from df columns
            df.columns = df.columns.str.strip()
            for col in FEATURE_COLUMNS:
                col_stripped = col.strip()
                if col_stripped in df.columns:
                    available_features.append(col_stripped)

        if not available_features:
            raise ValueError(
                f"No recognized feature columns found. "
                f"Expected columns like: {FEATURE_COLUMNS[:5]}... "
                f"Got columns: {df.columns.tolist()[:10]}..."
            )

        self.feature_columns = available_features
        logger.info(f"Found {len(available_features)} feature columns")

        # Convert feature columns to numeric
        for col in available_features:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        # Drop rows with NaN in feature columns
        before = len(df)
        df = df.dropna(subset=available_features)
        dropped = before - len(df)
        if dropped > 0:
            logger.info(f"Dropped {dropped} rows with NaN/invalid values")

        # Remove duplicates
        before = len(df)
        df = df.drop_duplicates(subset=available_features)
        deduped = before - len(df)
        if deduped > 0:
            logger.info(f"Removed {deduped} duplicate rows")

        logger.info(f"Cleaned dataframe: {len(df)} rows remaining")
        return df

    def fit_transform(
        self, df: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
        """
        Fit preprocessing pipeline on training data and transform.
        
        Returns:
            X: scaled feature matrix
            y: encoded label array
            metadata: non-feature columns for evidence extraction
        """
        df = self.clean_dataframe(df)

        # Extract features
        X = df[self.feature_columns].values.astype(np.float64)

        # Extract and encode labels
        label_col = None
        for candidate in [LABEL_COLUMN, LABEL_COLUMN.strip(), "Label", "label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(f"Label column not found. Available: {df.columns.tolist()}")

        # Clean labels
        labels = df[label_col].astype(str).str.strip()

        # Fit label encoder
        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(labels)
        logger.info(f"Label classes: {self.label_encoder.classes_.tolist()}")

        # Fit scaler
        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(X)

        # Extract metadata
        meta_cols = []
        for col in METADATA_COLUMNS:
            if col in df.columns:
                meta_cols.append(col)
            elif col.strip() in df.columns:
                meta_cols.append(col.strip())
        metadata = df[meta_cols].reset_index(drop=True) if meta_cols else pd.DataFrame()

        self._fitted = True
        logger.info(f"Preprocessing fitted: {X.shape[0]} samples, {X.shape[1]} features")
        return X, y, metadata

    def transform(
        self, df: pd.DataFrame
    ) -> Tuple[np.ndarray, pd.DataFrame]:
        """
        Transform new data using fitted preprocessing pipeline.
        Same transformation as training — no data leakage.
        
        Returns:
            X: scaled feature matrix
            metadata: non-feature columns
        """
        if not self._fitted:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform() or load().")

        df = self.clean_dataframe(df)

        # Use the same feature columns as training
        X = df[self.feature_columns].values.astype(np.float64)
        X = self.scaler.transform(X)

        # Extract metadata
        meta_cols = []
        for col in METADATA_COLUMNS:
            if col in df.columns:
                meta_cols.append(col)
            elif col.strip() in df.columns:
                meta_cols.append(col.strip())
        metadata = df[meta_cols].reset_index(drop=True) if meta_cols else pd.DataFrame()

        logger.info(f"Transformed: {X.shape[0]} samples, {X.shape[1]} features")
        return X, metadata

    def save(self, output_dir: Optional[Path] = None):
        """Save preprocessing artifacts for reuse during inference."""
        if not self._fitted:
            raise RuntimeError("Preprocessor not fitted.")

        save_dir = output_dir or MODELS_DIR
        save_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, save_dir / SCALER_FILE)
        joblib.dump(self.label_encoder, save_dir / LABEL_ENCODER_FILE)

        with open(save_dir / FEATURE_COLUMNS_FILE, "w") as f:
            json.dump(self.feature_columns, f, indent=2)

        logger.info(f"Preprocessing artifacts saved to {save_dir}")

    @classmethod
    def load(cls, model_dir: Optional[Path] = None) -> "DataPreprocessor":
        """Load saved preprocessing artifacts."""
        load_dir = model_dir or MODELS_DIR

        preprocessor = cls()
        preprocessor.scaler = joblib.load(load_dir / SCALER_FILE)
        preprocessor.label_encoder = joblib.load(load_dir / LABEL_ENCODER_FILE)

        with open(load_dir / FEATURE_COLUMNS_FILE, "r") as f:
            preprocessor.feature_columns = json.load(f)

        preprocessor._fitted = True
        logger.info(f"Preprocessing artifacts loaded from {load_dir}")
        return preprocessor

    def get_class_distribution(self, y: np.ndarray) -> Dict[str, int]:
        """Get class distribution for imbalance analysis."""
        if self.label_encoder is None:
            return {}
        classes = self.label_encoder.inverse_transform(np.unique(y))
        counts = np.bincount(y)
        return {str(cls): int(cnt) for cls, cnt in zip(classes, counts) if cnt > 0}
