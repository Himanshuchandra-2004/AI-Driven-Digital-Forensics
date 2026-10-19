"""
Risk / Severity scoring engine.

Formula:
    risk_score = (
        0.30 × normalized_anomaly_score +      # 0-100 from Isolation Forest
        0.25 × threat_confidence +              # 0-100 from Random Forest probability
        0.20 × threat_severity_weight +         # Based on threat category
        0.15 × frequency_score +                # Repeated suspicious activity
        0.10 × correlation_count_score          # Number of correlated events
    )

Severity Mapping:
    0-25  → LOW
    26-50 → MEDIUM
    51-75 → HIGH
    76-100 → CRITICAL

Threat Severity Weights (from CICIDS2017 attack categories):
    Heartbleed    = 95
    Bot           = 90
    DDoS          = 85
    Infiltration  = 85
    Web Attack    = 80
    DoS           = 75
    Brute Force   = 70
    PortScan      = 60
"""

from __future__ import annotations

from typing import Dict, Optional

# Threat category severity weights based on CICIDS2017 labels
THREAT_SEVERITY_WEIGHTS: Dict[str, float] = {
    "Heartbleed": 95.0,
    "Bot": 90.0,
    "DDoS": 85.0,
    "Infiltration": 85.0,
    "Web Attack - Brute Force": 80.0,
    "Web Attack - XSS": 80.0,
    "Web Attack - Sql Injection": 80.0,
    "Web Attack": 80.0,
    "DoS slowloris": 75.0,
    "DoS Slowhttptest": 75.0,
    "DoS Hulk": 75.0,
    "DoS GoldenEye": 75.0,
    "DoS": 75.0,
    "FTP-Patator": 70.0,
    "SSH-Patator": 70.0,
    "Brute Force": 70.0,
    "PortScan": 60.0,
    "BENIGN": 0.0,
}


def normalize_anomaly_score(raw_score: float) -> float:
    """
    Convert Isolation Forest anomaly score to 0-100 scale.
    
    Isolation Forest score_samples() returns values typically in [-1, 0]:
    - More negative = more anomalous
    - Closer to 0 = less anomalous
    - Positive values = clearly normal
    
    Mapping:
    - score <= -0.5 → risk 100 (very anomalous)
    - score >= 0.0  → risk 0 (normal)
    - Linear interpolation between
    """
    if raw_score <= -0.5:
        return 100.0
    elif raw_score >= 0.0:
        return 0.0
    else:
        # Linear mapping: -0.5 → 100, 0.0 → 0
        return max(0.0, min(100.0, (-raw_score / 0.5) * 100.0))


def get_threat_severity_weight(threat_class: str) -> float:
    """Get the severity weight for a threat classification."""
    # Try exact match first
    if threat_class in THREAT_SEVERITY_WEIGHTS:
        return THREAT_SEVERITY_WEIGHTS[threat_class]
    # Try partial match
    for key, weight in THREAT_SEVERITY_WEIGHTS.items():
        if key.lower() in threat_class.lower() or threat_class.lower() in key.lower():
            return weight
    # Unknown threat type gets moderate weight
    return 50.0


def calculate_risk_score(
    anomaly_score: Optional[float] = None,
    threat_confidence: Optional[float] = None,
    threat_class: Optional[str] = None,
    frequency_count: int = 1,
    correlation_count: int = 0,
    max_frequency: int = 10,
    max_correlations: int = 5,
) -> float:
    """
    Calculate composite risk score (0-100).
    
    Components:
    - 30% anomaly score (normalized 0-100)
    - 25% threat classification confidence (0-100)
    - 20% threat severity weight (based on category)
    - 15% frequency score (repeated suspicious activity)
    - 10% correlation count score (related events)
    """
    # Normalize anomaly score
    norm_anomaly = 0.0
    if anomaly_score is not None:
        norm_anomaly = normalize_anomaly_score(anomaly_score)

    # Threat confidence (already 0-1 from RF, convert to 0-100)
    norm_confidence = 0.0
    if threat_confidence is not None:
        norm_confidence = threat_confidence * 100.0

    # Threat severity weight
    threat_weight = 0.0
    if threat_class and threat_class != "BENIGN":
        threat_weight = get_threat_severity_weight(threat_class)

    # Frequency score (capped at max_frequency)
    frequency_score = min(frequency_count / max_frequency, 1.0) * 100.0

    # Correlation count score
    correlation_score = min(correlation_count / max_correlations, 1.0) * 100.0

    # Weighted composite
    risk = (
        0.30 * norm_anomaly
        + 0.25 * norm_confidence
        + 0.20 * threat_weight
        + 0.15 * frequency_score
        + 0.10 * correlation_score
    )

    return round(max(0.0, min(100.0, risk)), 2)


def classify_severity(risk_score: float) -> str:
    """Map risk score to severity level."""
    if risk_score >= 76:
        return "critical"
    elif risk_score >= 51:
        return "high"
    elif risk_score >= 26:
        return "medium"
    else:
        return "low"


def explain_risk_score(
    risk_score: float,
    anomaly_score: Optional[float] = None,
    threat_confidence: Optional[float] = None,
    threat_class: Optional[str] = None,
    frequency_count: int = 1,
    correlation_count: int = 0,
) -> str:
    """Generate a human-readable explanation of the risk score."""
    parts = []
    severity = classify_severity(risk_score)

    parts.append(f"Risk Score: {risk_score:.1f}/100 ({severity.upper()})")

    if anomaly_score is not None:
        norm = normalize_anomaly_score(anomaly_score)
        parts.append(f"  - Anomaly Score Contribution: {norm:.1f}/100 (weight: 30%)")

    if threat_confidence is not None:
        parts.append(
            f"  - Threat Confidence Contribution: {threat_confidence * 100:.1f}/100 (weight: 25%)"
        )

    if threat_class and threat_class != "BENIGN":
        w = get_threat_severity_weight(threat_class)
        parts.append(f"  - Threat Type '{threat_class}' Severity: {w:.0f}/100 (weight: 20%)")

    if frequency_count > 1:
        parts.append(f"  - Frequency: {frequency_count} related events (weight: 15%)")

    if correlation_count > 0:
        parts.append(f"  - Correlated Events: {correlation_count} (weight: 10%)")

    return "\n".join(parts)
