"""
Synthetic Demo Data Generator.

Generates realistic-looking network flow data for demonstration.
All data is clearly labeled as DEMO/SYNTHETIC.

Generates:
- Normal traffic (70%)
- DoS attack traffic (10%)
- DDoS traffic (5%)
- PortScan traffic (5%)
- Bot (botnet/C&C) traffic (5%)
- Brute Force traffic (3%)
- Web Attack traffic (2%)
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from ml.training.config import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# Realistic IP ranges
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [
    "10.0.0.1", "172.16.0.5", "8.8.8.8", "1.1.1.1",
    "203.0.113.10", "198.51.100.20", "185.220.101.42",
    "45.33.32.156", "104.236.198.48", "91.189.92.150",
]
SUSPICIOUS_IPS = [
    "185.220.101.42",  # Known Tor exit node pattern
    "91.121.43.180",   # Suspicious C&C pattern
    "45.227.255.206",  # Botnet C&C pattern
    "194.165.16.11",   # Malicious server pattern
]

ATTACK_LABELS = {
    "BENIGN": 0.70,
    "DoS Hulk": 0.10,
    "DDoS": 0.05,
    "PortScan": 0.05,
    "Bot": 0.05,
    "FTP-Patator": 0.03,
    "Web Attack - Brute Force": 0.02,
}


def generate_demo_data(n_records: int = 5000) -> pd.DataFrame:
    """
    Generate synthetic network flow data matching CICIDS2017 column format.
    
    All data is synthetic and clearly labeled as DEMO.
    """
    logger.info(f"Generating {n_records} synthetic demo records...")

    rng = np.random.RandomState(42)
    records = []

    # Determine label distribution
    labels = []
    for label, pct in ATTACK_LABELS.items():
        count = int(n_records * pct)
        labels.extend([label] * count)
    # Fill remainder with BENIGN
    while len(labels) < n_records:
        labels.append("BENIGN")
    random.shuffle(labels)

    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    for i in range(n_records):
        label = labels[i]
        ts = base_time + timedelta(seconds=i * 0.5)

        if label == "BENIGN":
            record = _generate_benign(rng, ts, i)
        elif "DoS" in label or "DDoS" in label:
            record = _generate_dos(rng, ts, i, label)
        elif label == "PortScan":
            record = _generate_portscan(rng, ts, i)
        elif label == "Bot":
            record = _generate_bot(rng, ts, i)
        elif "Patator" in label or "Brute" in label:
            record = _generate_bruteforce(rng, ts, i, label)
        elif "Web Attack" in label:
            record = _generate_webattack(rng, ts, i, label)
        else:
            record = _generate_benign(rng, ts, i)

        record[" Label"] = label
        record[" Timestamp"] = ts.strftime("%d/%m/%Y %H:%M:%S")
        records.append(record)

    df = pd.DataFrame(records)
    logger.info(f"Generated {len(df)} demo records with labels: {dict(pd.Series(labels).value_counts())}")
    return df


def _base_record(rng, ts, idx, src_ip, dst_ip, src_port, dst_port, protocol=6):
    """Create base record with metadata columns."""
    return {
        "Flow ID": f"demo-flow-{idx}",
        " Source IP": src_ip,
        " Source Port": src_port,
        " Destination IP": dst_ip,
        " Destination Port": dst_port,
        " Protocol": protocol,
    }


def _generate_benign(rng, ts, idx):
    """Normal web browsing / DNS / email traffic."""
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    dst_port = random.choice([80, 443, 53, 8080, 25, 110])
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), dst_port)
    r.update({
        " Destination Port": dst_port,
        " Flow Duration": rng.randint(100, 50000),
        " Total Fwd Packets": rng.randint(1, 20),
        " Total Backward Packets": rng.randint(1, 15),
        "Total Length of Fwd Packets": rng.randint(64, 5000),
        " Total Length of Bwd Packets": rng.randint(64, 10000),
        " Fwd Packet Length Max": rng.randint(64, 1500),
        " Fwd Packet Length Mean": round(rng.uniform(64, 800), 2),
        " Bwd Packet Length Max": rng.randint(64, 1500),
        " Bwd Packet Length Mean": round(rng.uniform(64, 800), 2),
        " Flow Bytes/s": round(rng.uniform(100, 100000), 2),
        " Flow Packets/s": round(rng.uniform(1, 500), 2),
        " Flow IAT Mean": round(rng.uniform(100, 50000), 2),
        " Flow IAT Std": round(rng.uniform(0, 30000), 2),
        " Fwd IAT Total": rng.randint(100, 50000),
        " Bwd IAT Total": rng.randint(100, 50000),
        " Fwd PSH Flags": rng.randint(0, 2),
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(1, 200), 2),
        " Bwd Packets/s": round(rng.uniform(1, 200), 2),
        " Min Packet Length": rng.randint(0, 64),
        " Max Packet Length": rng.randint(500, 1500),
        " Packet Length Mean": round(rng.uniform(64, 800), 2),
        " Packet Length Std": round(rng.uniform(0, 500), 2),
        " Packet Length Variance": round(rng.uniform(0, 250000), 2),
        " FIN Flag Count": rng.randint(0, 2),
        " SYN Flag Count": rng.randint(0, 2),
        " RST Flag Count": 0,
        " ACK Flag Count": rng.randint(0, 5),
        " Down/Up Ratio": round(rng.uniform(0, 3), 2),
        " Average Packet Size": round(rng.uniform(64, 800), 2),
        " Avg Fwd Segment Size": round(rng.uniform(64, 800), 2),
        " Avg Bwd Segment Size": round(rng.uniform(64, 800), 2),
        "Init_Win_bytes_forward": rng.randint(0, 65535),
        " Init_Win_bytes_backward": rng.randint(0, 65535),
        " Active Mean": round(rng.uniform(0, 5000), 2),
        " Idle Mean": round(rng.uniform(0, 100000), 2),
    })
    return r


def _generate_dos(rng, ts, idx, label):
    """DoS/DDoS — high packet rate, many forward packets, high bytes/s."""
    src = random.choice(EXTERNAL_IPS + SUSPICIOUS_IPS)
    dst = random.choice(INTERNAL_IPS)
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), 80)
    r.update({
        " Destination Port": 80,
        " Flow Duration": rng.randint(1, 1000),
        " Total Fwd Packets": rng.randint(100, 5000),
        " Total Backward Packets": rng.randint(0, 5),
        "Total Length of Fwd Packets": rng.randint(50000, 500000),
        " Total Length of Bwd Packets": rng.randint(0, 500),
        " Fwd Packet Length Max": rng.randint(1000, 1500),
        " Fwd Packet Length Mean": round(rng.uniform(500, 1400), 2),
        " Bwd Packet Length Max": rng.randint(0, 100),
        " Bwd Packet Length Mean": round(rng.uniform(0, 50), 2),
        " Flow Bytes/s": round(rng.uniform(500000, 5000000), 2),
        " Flow Packets/s": round(rng.uniform(1000, 50000), 2),
        " Flow IAT Mean": round(rng.uniform(0, 100), 2),
        " Flow IAT Std": round(rng.uniform(0, 50), 2),
        " Fwd IAT Total": rng.randint(1, 500),
        " Bwd IAT Total": 0,
        " Fwd PSH Flags": rng.randint(0, 1),
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(5000, 50000), 2),
        " Bwd Packets/s": round(rng.uniform(0, 10), 2),
        " Min Packet Length": rng.randint(0, 10),
        " Max Packet Length": rng.randint(1000, 1500),
        " Packet Length Mean": round(rng.uniform(400, 1400), 2),
        " Packet Length Std": round(rng.uniform(200, 600), 2),
        " Packet Length Variance": round(rng.uniform(40000, 360000), 2),
        " FIN Flag Count": 0,
        " SYN Flag Count": rng.randint(1, 5),
        " RST Flag Count": rng.randint(0, 3),
        " ACK Flag Count": rng.randint(0, 2),
        " Down/Up Ratio": 0,
        " Average Packet Size": round(rng.uniform(400, 1400), 2),
        " Avg Fwd Segment Size": round(rng.uniform(400, 1400), 2),
        " Avg Bwd Segment Size": 0,
        "Init_Win_bytes_forward": rng.randint(0, 1000),
        " Init_Win_bytes_backward": 0,
        " Active Mean": round(rng.uniform(0, 100), 2),
        " Idle Mean": 0,
    })
    return r


def _generate_portscan(rng, ts, idx):
    """PortScan — many short flows to different destination ports."""
    src = random.choice(SUSPICIOUS_IPS)
    dst = random.choice(INTERNAL_IPS)
    dst_port = rng.randint(1, 65535)
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), dst_port)
    r.update({
        " Destination Port": dst_port,
        " Flow Duration": rng.randint(0, 100),
        " Total Fwd Packets": rng.randint(1, 3),
        " Total Backward Packets": rng.randint(0, 2),
        "Total Length of Fwd Packets": rng.randint(0, 200),
        " Total Length of Bwd Packets": rng.randint(0, 200),
        " Fwd Packet Length Max": rng.randint(0, 100),
        " Fwd Packet Length Mean": round(rng.uniform(0, 80), 2),
        " Bwd Packet Length Max": rng.randint(0, 100),
        " Bwd Packet Length Mean": round(rng.uniform(0, 60), 2),
        " Flow Bytes/s": round(rng.uniform(0, 50000), 2),
        " Flow Packets/s": round(rng.uniform(0, 5000), 2),
        " Flow IAT Mean": round(rng.uniform(0, 500), 2),
        " Flow IAT Std": round(rng.uniform(0, 200), 2),
        " Fwd IAT Total": rng.randint(0, 200),
        " Bwd IAT Total": 0,
        " Fwd PSH Flags": 0,
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(0, 10000), 2),
        " Bwd Packets/s": 0,
        " Min Packet Length": 0,
        " Max Packet Length": rng.randint(40, 100),
        " Packet Length Mean": round(rng.uniform(0, 80), 2),
        " Packet Length Std": round(rng.uniform(0, 40), 2),
        " Packet Length Variance": round(rng.uniform(0, 1600), 2),
        " FIN Flag Count": 0,
        " SYN Flag Count": 1,
        " RST Flag Count": rng.randint(0, 1),
        " ACK Flag Count": 0,
        " Down/Up Ratio": 0,
        " Average Packet Size": round(rng.uniform(0, 80), 2),
        " Avg Fwd Segment Size": round(rng.uniform(0, 80), 2),
        " Avg Bwd Segment Size": 0,
        "Init_Win_bytes_forward": rng.randint(0, 65535),
        " Init_Win_bytes_backward": 0,
        " Active Mean": 0,
        " Idle Mean": 0,
    })
    return r


def _generate_bot(rng, ts, idx):
    """Botnet/C&C — periodic beaconing, low volume, suspicious destinations."""
    src = random.choice(INTERNAL_IPS[:5])
    dst = random.choice(SUSPICIOUS_IPS)
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), 443)
    r.update({
        " Destination Port": 443,
        " Flow Duration": rng.randint(5000, 100000),
        " Total Fwd Packets": rng.randint(5, 30),
        " Total Backward Packets": rng.randint(5, 30),
        "Total Length of Fwd Packets": rng.randint(200, 5000),
        " Total Length of Bwd Packets": rng.randint(200, 5000),
        " Fwd Packet Length Max": rng.randint(100, 500),
        " Fwd Packet Length Mean": round(rng.uniform(50, 300), 2),
        " Bwd Packet Length Max": rng.randint(100, 500),
        " Bwd Packet Length Mean": round(rng.uniform(50, 300), 2),
        " Flow Bytes/s": round(rng.uniform(50, 5000), 2),
        " Flow Packets/s": round(rng.uniform(1, 50), 2),
        " Flow IAT Mean": round(rng.uniform(1000, 50000), 2),
        " Flow IAT Std": round(rng.uniform(100, 5000), 2),
        " Fwd IAT Total": rng.randint(5000, 100000),
        " Bwd IAT Total": rng.randint(5000, 100000),
        " Fwd PSH Flags": rng.randint(0, 3),
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(1, 30), 2),
        " Bwd Packets/s": round(rng.uniform(1, 30), 2),
        " Min Packet Length": rng.randint(0, 40),
        " Max Packet Length": rng.randint(200, 500),
        " Packet Length Mean": round(rng.uniform(50, 250), 2),
        " Packet Length Std": round(rng.uniform(30, 200), 2),
        " Packet Length Variance": round(rng.uniform(900, 40000), 2),
        " FIN Flag Count": rng.randint(0, 1),
        " SYN Flag Count": rng.randint(0, 1),
        " RST Flag Count": 0,
        " ACK Flag Count": rng.randint(1, 5),
        " Down/Up Ratio": round(rng.uniform(0.5, 2), 2),
        " Average Packet Size": round(rng.uniform(50, 250), 2),
        " Avg Fwd Segment Size": round(rng.uniform(50, 250), 2),
        " Avg Bwd Segment Size": round(rng.uniform(50, 250), 2),
        "Init_Win_bytes_forward": rng.randint(100, 10000),
        " Init_Win_bytes_backward": rng.randint(100, 10000),
        " Active Mean": round(rng.uniform(100, 5000), 2),
        " Idle Mean": round(rng.uniform(10000, 100000), 2),
    })
    return r


def _generate_bruteforce(rng, ts, idx, label):
    """Brute force — many short flows to SSH/FTP ports."""
    src = random.choice(SUSPICIOUS_IPS)
    dst = random.choice(INTERNAL_IPS)
    dst_port = 22 if "SSH" in label else 21
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), dst_port)
    r.update({
        " Destination Port": dst_port,
        " Flow Duration": rng.randint(100, 5000),
        " Total Fwd Packets": rng.randint(5, 20),
        " Total Backward Packets": rng.randint(3, 15),
        "Total Length of Fwd Packets": rng.randint(200, 3000),
        " Total Length of Bwd Packets": rng.randint(100, 2000),
        " Fwd Packet Length Max": rng.randint(100, 500),
        " Fwd Packet Length Mean": round(rng.uniform(50, 300), 2),
        " Bwd Packet Length Max": rng.randint(50, 300),
        " Bwd Packet Length Mean": round(rng.uniform(30, 200), 2),
        " Flow Bytes/s": round(rng.uniform(1000, 50000), 2),
        " Flow Packets/s": round(rng.uniform(10, 500), 2),
        " Flow IAT Mean": round(rng.uniform(50, 2000), 2),
        " Flow IAT Std": round(rng.uniform(10, 1000), 2),
        " Fwd IAT Total": rng.randint(100, 5000),
        " Bwd IAT Total": rng.randint(100, 3000),
        " Fwd PSH Flags": rng.randint(1, 5),
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(10, 300), 2),
        " Bwd Packets/s": round(rng.uniform(5, 200), 2),
        " Min Packet Length": rng.randint(0, 20),
        " Max Packet Length": rng.randint(200, 500),
        " Packet Length Mean": round(rng.uniform(50, 250), 2),
        " Packet Length Std": round(rng.uniform(20, 200), 2),
        " Packet Length Variance": round(rng.uniform(400, 40000), 2),
        " FIN Flag Count": rng.randint(0, 1),
        " SYN Flag Count": rng.randint(1, 3),
        " RST Flag Count": rng.randint(0, 2),
        " ACK Flag Count": rng.randint(1, 5),
        " Down/Up Ratio": round(rng.uniform(0.3, 1.5), 2),
        " Average Packet Size": round(rng.uniform(50, 250), 2),
        " Avg Fwd Segment Size": round(rng.uniform(50, 250), 2),
        " Avg Bwd Segment Size": round(rng.uniform(30, 200), 2),
        "Init_Win_bytes_forward": rng.randint(100, 30000),
        " Init_Win_bytes_backward": rng.randint(100, 30000),
        " Active Mean": round(rng.uniform(50, 2000), 2),
        " Idle Mean": round(rng.uniform(100, 5000), 2),
    })
    return r


def _generate_webattack(rng, ts, idx, label):
    """Web attack — HTTP traffic with unusual patterns."""
    src = random.choice(SUSPICIOUS_IPS)
    dst = random.choice(INTERNAL_IPS)
    r = _base_record(rng, ts, idx, src, dst, rng.randint(1024, 65535), 80)
    r.update({
        " Destination Port": 80,
        " Flow Duration": rng.randint(500, 30000),
        " Total Fwd Packets": rng.randint(10, 50),
        " Total Backward Packets": rng.randint(5, 30),
        "Total Length of Fwd Packets": rng.randint(5000, 50000),
        " Total Length of Bwd Packets": rng.randint(1000, 20000),
        " Fwd Packet Length Max": rng.randint(500, 1500),
        " Fwd Packet Length Mean": round(rng.uniform(200, 1000), 2),
        " Bwd Packet Length Max": rng.randint(200, 1000),
        " Bwd Packet Length Mean": round(rng.uniform(100, 500), 2),
        " Flow Bytes/s": round(rng.uniform(10000, 500000), 2),
        " Flow Packets/s": round(rng.uniform(50, 2000), 2),
        " Flow IAT Mean": round(rng.uniform(100, 5000), 2),
        " Flow IAT Std": round(rng.uniform(50, 3000), 2),
        " Fwd IAT Total": rng.randint(500, 30000),
        " Bwd IAT Total": rng.randint(200, 15000),
        " Fwd PSH Flags": rng.randint(1, 10),
        " Fwd URG Flags": 0,
        "Fwd Packets/s": round(rng.uniform(50, 1000), 2),
        " Bwd Packets/s": round(rng.uniform(20, 500), 2),
        " Min Packet Length": rng.randint(0, 20),
        " Max Packet Length": rng.randint(500, 1500),
        " Packet Length Mean": round(rng.uniform(200, 800), 2),
        " Packet Length Std": round(rng.uniform(100, 500), 2),
        " Packet Length Variance": round(rng.uniform(10000, 250000), 2),
        " FIN Flag Count": rng.randint(0, 2),
        " SYN Flag Count": rng.randint(0, 2),
        " RST Flag Count": rng.randint(0, 1),
        " ACK Flag Count": rng.randint(2, 10),
        " Down/Up Ratio": round(rng.uniform(0.2, 1.0), 2),
        " Average Packet Size": round(rng.uniform(200, 800), 2),
        " Avg Fwd Segment Size": round(rng.uniform(200, 800), 2),
        " Avg Bwd Segment Size": round(rng.uniform(100, 400), 2),
        "Init_Win_bytes_forward": rng.randint(1000, 65535),
        " Init_Win_bytes_backward": rng.randint(1000, 65535),
        " Active Mean": round(rng.uniform(200, 5000), 2),
        " Idle Mean": round(rng.uniform(500, 10000), 2),
    })
    return r
