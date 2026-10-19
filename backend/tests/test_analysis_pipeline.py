"""
Analysis Pipeline & Risk Scoring Tests.

Covers: risk scoring formula, severity classification, anomaly normalization,
risk explanation, hash integrity, system endpoints, and health checks.
"""

from __future__ import annotations

import pytest
from tests.conftest import auth_headers


class TestRiskScoringFormula:
    """Test the multi-component risk scoring formula."""

    def test_all_components_maximum(self):
        """Maximum inputs should produce near-maximum score."""
        from app.services.risk_service import calculate_risk_score

        score = calculate_risk_score(
            anomaly_score=-0.5,      # Max anomaly
            threat_confidence=1.0,    # Max confidence
            threat_class="Heartbleed",  # Highest severity weight (95)
            frequency_count=10,       # Max frequency
            correlation_count=5,      # Max correlation
        )
        assert score >= 90

    def test_all_components_minimum(self):
        """Minimum inputs should produce near-zero score."""
        from app.services.risk_service import calculate_risk_score

        score = calculate_risk_score(
            anomaly_score=0.1,        # Normal
            threat_confidence=0.0,    # No confidence
            threat_class="BENIGN",    # Benign
            frequency_count=1,
            correlation_count=0,
        )
        assert score < 20

    def test_anomaly_only(self):
        """Score with only anomaly component."""
        from app.services.risk_service import calculate_risk_score

        score = calculate_risk_score(anomaly_score=-0.5)
        # 30% * 100 = 30, plus 15% * 10 (frequency=1) = 1.5
        assert 25 < score < 40

    def test_threat_only(self):
        """Score with only threat component."""
        from app.services.risk_service import calculate_risk_score

        score = calculate_risk_score(
            threat_confidence=0.95,
            threat_class="DDoS",
        )
        assert score > 30

    def test_combined_high_risk(self):
        """Combined anomaly + threat should produce high risk."""
        from app.services.risk_service import calculate_risk_score

        score = calculate_risk_score(
            anomaly_score=-0.4,
            threat_confidence=0.9,
            threat_class="Bot",
            frequency_count=5,
            correlation_count=3,
        )
        assert score >= 70

    def test_score_always_in_range(self):
        """Score must always be between 0 and 100."""
        from app.services.risk_service import calculate_risk_score

        for anomaly in [-1.0, -0.5, -0.2, 0.0, 0.5]:
            for confidence in [0.0, 0.5, 1.0]:
                for threat in ["BENIGN", "DoS", "DDoS", "Bot"]:
                    score = calculate_risk_score(
                        anomaly_score=anomaly,
                        threat_confidence=confidence,
                        threat_class=threat,
                    )
                    assert 0 <= score <= 100, f"Score {score} out of range"


class TestSeverityClassification:
    """Test severity level mapping."""

    def test_severity_boundaries(self):
        """Test exact boundary values."""
        from app.services.risk_service import classify_severity

        assert classify_severity(0) == "low"
        assert classify_severity(25) == "low"
        assert classify_severity(25.99) == "low"
        assert classify_severity(26) == "medium"
        assert classify_severity(50) == "medium"
        assert classify_severity(50.99) == "medium"
        assert classify_severity(51) == "high"
        assert classify_severity(75) == "high"
        assert classify_severity(75.99) == "high"
        assert classify_severity(76) == "critical"
        assert classify_severity(100) == "critical"


class TestAnomalyScoreNormalization:
    """Test Isolation Forest score normalization."""

    def test_normalization_bounds(self):
        """Score normalization must map to 0-100."""
        from app.services.risk_service import normalize_anomaly_score

        assert normalize_anomaly_score(-0.5) == 100.0
        assert normalize_anomaly_score(0.0) == 0.0
        assert normalize_anomaly_score(-1.0) == 100.0  # Clamped at 100
        assert normalize_anomaly_score(0.5) == 0.0      # Clamped at 0

    def test_normalization_midpoint(self):
        """Midpoint score should normalize to ~50."""
        from app.services.risk_service import normalize_anomaly_score

        score = normalize_anomaly_score(-0.25)
        assert 45 < score < 55  # Should be around 50


class TestRiskExplanation:
    """Test human-readable risk score explanations."""

    def test_explanation_includes_components(self):
        """Explanation should list all contributing components."""
        from app.services.risk_service import explain_risk_score

        explanation = explain_risk_score(
            risk_score=82.5,
            anomaly_score=-0.4,
            threat_confidence=0.9,
            threat_class="Bot",
            frequency_count=5,
            correlation_count=3,
        )
        assert "82.5" in explanation
        assert "Bot" in explanation
        assert "30%" in explanation
        assert "25%" in explanation

    def test_explanation_minimal_input(self):
        """Explanation with minimal input should still work."""
        from app.services.risk_service import explain_risk_score

        explanation = explain_risk_score(risk_score=15.0)
        assert "15.0" in explanation
        assert "LOW" in explanation


class TestHashIntegrity:
    """Test evidence hash chaining and tamper detection."""

    def test_hash_chain_sequence(self):
        """Hash chain should create sequential dependencies."""
        from app.services.hash_service import compute_evidence_hash

        data1 = {"id": "ev-001", "src_ip": "192.168.1.1"}
        data2 = {"id": "ev-002", "src_ip": "192.168.1.2"}
        data3 = {"id": "ev-003", "src_ip": "192.168.1.3"}

        h1 = compute_evidence_hash(data1, previous_hash=None)
        h2 = compute_evidence_hash(data2, previous_hash=h1)
        h3 = compute_evidence_hash(data3, previous_hash=h2)

        # All hashes should be different
        assert len({h1, h2, h3}) == 3

        # Breaking the chain (wrong previous) should give different result
        h2_broken = compute_evidence_hash(data2, previous_hash="tampered")
        assert h2 != h2_broken

    def test_canonical_data_sorted(self):
        """Hash should be order-independent (sorted keys)."""
        from app.services.hash_service import compute_evidence_hash

        data_a = {"z": 1, "a": 2, "m": 3}
        data_b = {"a": 2, "m": 3, "z": 1}
        assert compute_evidence_hash(data_a) == compute_evidence_hash(data_b)


@pytest.mark.asyncio
class TestSystemEndpoints:
    """Test system monitoring endpoints."""

    async def test_health_check(self, client, db_session):
        """Basic health check should return healthy."""
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"

    async def test_deep_health_check(self, client, db_session):
        """Deep health check should verify subsystems."""
        response = await client.get("/api/system/health")
        assert response.status_code == 200
        data = response.json()
        assert "checks" in data
        assert "database" in data["checks"]
        assert data["checks"]["database"]["status"] == "healthy"

    async def test_system_info(self, client, db_session):
        """System info should return version and environment."""
        response = await client.get("/api/system/info")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.0"
        assert "python_version" in data["environment"]
        assert "database_type" in data["configuration"]

    async def test_system_metrics_requires_auth(self, client, db_session):
        """Metrics endpoint should require authentication."""
        response = await client.get("/api/system/metrics")
        assert response.status_code in (401, 403)

    async def test_system_metrics_authenticated(self, client, investigator_user):
        """Authenticated user can access metrics."""
        _, token = investigator_user
        response = await client.get(
            "/api/system/metrics",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "uptime_since" in data


@pytest.mark.asyncio
class TestTimelineEndpoints:
    """Test timeline and analysis endpoints."""

    async def test_timeline_empty_case(self, client, investigator_user, sample_case):
        """Timeline for case with no events should return empty."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/timeline",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 0
        assert data["events"] == []

    async def test_network_graph_empty(self, client, investigator_user, sample_case):
        """Network graph for empty case should have no nodes/edges."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/network-graph",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["summary"]["total_nodes"] == 0
        assert data["summary"]["total_edges"] == 0

    async def test_case_statistics_empty(self, client, investigator_user, sample_case):
        """Statistics for empty case should return zero counts."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/statistics",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score_statistics"]["total_scored"] == 0
