"""
Backend Tests — covers authentication, evidence hashing, risk scoring, and more.
"""

import hashlib
import json
import pytest

# ---- Test Hash Service ----
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.hash_service import compute_evidence_hash, get_evidence_canonical_data
from app.services.risk_service import (
    calculate_risk_score,
    classify_severity,
    normalize_anomaly_score,
    explain_risk_score,
)


class TestHashService:
    """Test SHA-256 evidence hashing and integrity verification."""

    def test_compute_hash_deterministic(self):
        """Same data produces same hash."""
        data = {"evidence_id": "123", "src_ip": "192.168.1.1", "threat": "DoS"}
        h1 = compute_evidence_hash(data)
        h2 = compute_evidence_hash(data)
        assert h1 == h2

    def test_compute_hash_changes_on_modification(self):
        """Modified data produces different hash — tamper detection."""
        data1 = {"evidence_id": "123", "src_ip": "192.168.1.1", "threat": "DoS"}
        data2 = {"evidence_id": "123", "src_ip": "192.168.1.1", "threat": "DDoS"}
        h1 = compute_evidence_hash(data1)
        h2 = compute_evidence_hash(data2)
        assert h1 != h2

    def test_hash_chaining(self):
        """Hash chaining includes previous hash."""
        data = {"evidence_id": "123", "src_ip": "192.168.1.1"}
        h_no_chain = compute_evidence_hash(data)
        h_with_chain = compute_evidence_hash(data, previous_hash="abc123")
        assert h_no_chain != h_with_chain

    def test_hash_is_sha256(self):
        """Hash output is valid SHA-256 (64 hex characters)."""
        data = {"test": "value"}
        h = compute_evidence_hash(data)
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)

    def test_tamper_detection_critical(self):
        """
        CRITICAL INTEGRITY TEST:
        Create evidence → hash → modify → verify → MUST detect modification.
        """
        # Simulate evidence record
        original_data = {
            "evidence_id": "ev-001",
            "case_id": "case-001",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "threat": "Bot",
            "severity": "high",
        }

        # Step 1: Compute original hash
        original_hash = compute_evidence_hash(original_data)

        # Step 2: Modify the evidence (simulate tampering)
        tampered_data = original_data.copy()
        tampered_data["severity"] = "low"  # Tampered!

        # Step 3: Recompute hash
        tampered_hash = compute_evidence_hash(tampered_data)

        # Step 4: Verify — hashes MUST differ
        assert original_hash != tampered_hash, "INTEGRITY CHECK FAILED: tampered data was not detected!"


class TestRiskService:
    """Test risk scoring formula and severity classification."""

    def test_classify_severity_low(self):
        assert classify_severity(10) == "low"
        assert classify_severity(25) == "low"

    def test_classify_severity_medium(self):
        assert classify_severity(26) == "medium"
        assert classify_severity(50) == "medium"

    def test_classify_severity_high(self):
        assert classify_severity(51) == "high"
        assert classify_severity(75) == "high"

    def test_classify_severity_critical(self):
        assert classify_severity(76) == "critical"
        assert classify_severity(100) == "critical"

    def test_normalize_anomaly_score(self):
        """Test Isolation Forest score normalization to 0-100."""
        assert normalize_anomaly_score(-0.5) == 100.0
        assert normalize_anomaly_score(0.0) == 0.0
        assert 0 < normalize_anomaly_score(-0.25) < 100

    def test_risk_score_range(self):
        """Risk score must always be between 0 and 100."""
        score = calculate_risk_score(
            anomaly_score=-0.3,
            threat_confidence=0.9,
            threat_class="DDoS",
            frequency_count=5,
            correlation_count=3,
        )
        assert 0 <= score <= 100

    def test_benign_low_risk(self):
        """Benign classification should produce low risk."""
        score = calculate_risk_score(
            anomaly_score=0.1,  # Normal
            threat_confidence=0.95,
            threat_class="BENIGN",
            frequency_count=1,
            correlation_count=0,
        )
        assert score < 40  # Should be low-medium

    def test_explain_risk_produces_output(self):
        """Risk explanation should produce human-readable text."""
        explanation = explain_risk_score(
            risk_score=75.5,
            anomaly_score=-0.4,
            threat_confidence=0.85,
            threat_class="Bot",
            frequency_count=3,
            correlation_count=2,
        )
        assert "75.5" in explanation
        assert "Bot" in explanation


class TestSecurity:
    """Test security utilities."""

    def test_password_hashing(self):
        from app.core.security import hash_password, verify_password

        pw = "test_password_123"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed)
        assert not verify_password("wrong_password", hashed)

    def test_jwt_token_creation(self):
        from app.core.security import create_access_token, decode_access_token

        data = {"sub": "user-123", "role": "investigator"}
        token = create_access_token(data)
        assert token

        decoded = decode_access_token(token)
        assert decoded is not None
        assert decoded["sub"] == "user-123"
        assert decoded["role"] == "investigator"

    def test_jwt_invalid_token(self):
        from app.core.security import decode_access_token

        result = decode_access_token("invalid-token")
        assert result is None
