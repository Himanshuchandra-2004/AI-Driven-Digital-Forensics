"""
ML Pipeline Configuration.

Defines features, hyperparameters, and dataset settings.
All settings are documented and justified.
"""

from __future__ import annotations

from pathlib import Path

# ---- Paths ----
ML_ROOT = Path(__file__).parent.parent
DATA_RAW_DIR = ML_ROOT / "data" / "raw"
DATA_PROCESSED_DIR = ML_ROOT / "data" / "processed"
MODELS_DIR = ML_ROOT / "models"

# ---- Dataset ----
DATASET_NAME = "CICIDS2017"
DATASET_SOURCE = "https://www.unb.ca/cic/datasets/ids-2017.html"

# Column name for the label in CICIDS2017
LABEL_COLUMN = " Label"  # Note: CICIDS2017 has a leading space in column name

# ---- Feature Columns ----
# These are meaningful network-flow features from CICIDS2017.
# Source IP, Destination IP are NOT used as numeric features for ML (would be data leakage).
# They are preserved as metadata for evidence extraction and correlation.
FEATURE_COLUMNS = [
    " Destination Port",
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Mean",
    " Bwd Packet Length Max",
    " Bwd Packet Length Mean",
    " Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",
    " Flow IAT Std",
    " Fwd IAT Total",
    " Bwd IAT Total",
    " Fwd PSH Flags",
    " Fwd URG Flags",
    "Fwd Packets/s",
    " Bwd Packets/s",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Packet Length Variance",
    " FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " ACK Flag Count",
    " Down/Up Ratio",
    " Average Packet Size",
    " Avg Fwd Segment Size",
    " Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",
    " Active Mean",
    " Idle Mean",
]

# Metadata columns (preserved but NOT used as ML features)
METADATA_COLUMNS = [
    " Source IP",
    " Source Port",
    " Destination IP",
    " Destination Port",
    " Protocol",
    " Timestamp",
    "Flow ID",
]

# ---- Isolation Forest Hyperparameters ----
IF_PARAMS = {
    "n_estimators": 200,
    "max_samples": "auto",
    "contamination": 0.1,  # Expected proportion of anomalies
    "random_state": 42,
    "n_jobs": -1,
}

# ---- Random Forest Hyperparameters ----
RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "class_weight": "balanced",  # Handle class imbalance
    "random_state": 42,
    "n_jobs": -1,
}

# ---- Training ----
TEST_SIZE = 0.2
RANDOM_STATE = 42
MAX_TRAINING_SAMPLES = 500_000  # Limit for academic prototype to keep training reasonable

# ---- Model file names ----
IF_MODEL_FILE = "isolation_forest_v1.joblib"
RF_MODEL_FILE = "random_forest_v1.joblib"
SCALER_FILE = "scaler_v1.joblib"
LABEL_ENCODER_FILE = "label_encoder_v1.joblib"
FEATURE_COLUMNS_FILE = "feature_columns.json"
