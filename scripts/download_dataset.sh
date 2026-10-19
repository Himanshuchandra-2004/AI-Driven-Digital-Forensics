#!/usr/bin/env bash
# ============================================================
# Download CICIDS2017 Dataset
# ============================================================
# Downloads the CICIDS2017 MachineLearningCSV dataset from UNB.
# Source: https://www.unb.ca/cic/datasets/ids-2017.html
#
# The dataset is approximately 1GB compressed.
# After extraction, CSV files should be placed in ml/data/raw/
#
# Usage:
#   chmod +x scripts/download_dataset.sh
#   ./scripts/download_dataset.sh
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/ml/data/raw"

mkdir -p "$DATA_DIR"

echo "============================================================"
echo "  CICIDS2017 Dataset Download"
echo "============================================================"
echo ""
echo "The CICIDS2017 dataset must be downloaded manually from:"
echo ""
echo "  https://www.unb.ca/cic/datasets/ids-2017.html"
echo ""
echo "Steps:"
echo "  1. Go to the URL above"
echo "  2. Download 'MachineLearningCSV.zip'"
echo "  3. Extract the ZIP file"
echo "  4. Place all CSV files in: $DATA_DIR"
echo ""
echo "Expected files after extraction:"
echo "  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
echo "  - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
echo "  - Friday-WorkingHours-Morning.pcap_ISCX.csv"
echo "  - Monday-WorkingHours.pcap_ISCX.csv"
echo "  - Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
echo "  - Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
echo "  - Tuesday-WorkingHours.pcap_ISCX.csv"
echo "  - Wednesday-workingHours.pcap_ISCX.csv"
echo ""
echo "NOTE: The project works WITHOUT the full dataset."
echo "      Use the demo mode or run 'python -m scripts.train_on_demo'"
echo "      to train on synthetic data instead."
echo "============================================================"
