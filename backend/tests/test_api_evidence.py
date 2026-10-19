"""
Evidence & Integrity Tests.

Covers: evidence listing, filtering, integrity verification,
enrichment service, and chain of custody.
"""

from __future__ import annotations

import uuid

import pytest
from tests.conftest import auth_headers


@pytest.mark.asyncio
class TestEvidenceEndpoints:
    """Test evidence API endpoints."""

    async def test_list_evidence_empty_case(self, client, investigator_user, sample_case):
        """Listing evidence for a case with no evidence returns empty list."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/evidence",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_evidence_not_found(self, client, investigator_user):
        """Getting non-existent evidence returns 404."""
        _, token = investigator_user
        response = await client.get(
            f"/api/evidence/{uuid.uuid4()}",
            headers=auth_headers(token),
        )
        assert response.status_code == 404

    async def test_list_threats_empty(self, client, investigator_user, sample_case):
        """Listing threats for empty case returns empty."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/threats",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_list_anomalies_empty(self, client, investigator_user, sample_case):
        """Listing anomalies for empty case returns empty."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/anomalies",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_evidence_summary_empty(self, client, investigator_user, sample_case):
        """Evidence summary for empty case returns zero counts."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}/evidence/summary",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_evidence"] == 0
        assert data["integrity"]["coverage_pct"] == 0


@pytest.mark.asyncio
class TestEnrichmentService:
    """Test the evidence enrichment service directly."""

    def test_classify_private_ip(self):
        """Private IPs should be classified correctly."""
        from app.services.enrichment_service import classify_ip

        result = classify_ip("192.168.1.100")
        assert result["valid"] is True
        assert result["is_private"] is True
        assert result["network_type"] == "private"
        assert "RFC 1918" in result["rfc_classification"]

    def test_classify_public_ip(self):
        """Public IPs should be classified as external."""
        from app.services.enrichment_service import classify_ip

        result = classify_ip("8.8.8.8")
        assert result["valid"] is True
        assert result["is_private"] is False
        assert result["network_type"] == "public"
        assert result["risk_indicator"] == "external"

    def test_classify_loopback(self):
        """Loopback IP should be identified."""
        from app.services.enrichment_service import classify_ip

        result = classify_ip("127.0.0.1")
        assert result["is_loopback"] is True
        assert result["network_type"] == "loopback"

    def test_classify_invalid_ip(self):
        """Invalid IP should return error."""
        from app.services.enrichment_service import classify_ip

        result = classify_ip("not-an-ip")
        assert result["valid"] is False

    def test_enrich_known_port(self):
        """Well-known ports should have service info."""
        from app.services.enrichment_service import enrich_port

        result = enrich_port(443)
        assert result["known"] is True
        assert result["service"] == "HTTPS"
        assert result["category"] == "web"
        assert result["is_privileged"] is True

    def test_enrich_attack_port(self):
        """Attack ports should be flagged."""
        from app.services.enrichment_service import enrich_port

        result = enrich_port(22)
        assert result["is_common_target"] is True
        assert "brute force" in result["attack_vector"].lower()

    def test_enrich_ephemeral_port(self):
        """Ephemeral ports should be identified."""
        from app.services.enrichment_service import enrich_port

        result = enrich_port(50000)
        assert result["is_ephemeral"] is True
        assert result["is_privileged"] is False

    def test_resolve_protocol_tcp(self):
        """TCP protocol number should resolve correctly."""
        from app.services.enrichment_service import resolve_protocol

        result = resolve_protocol("6")
        assert result["name"] == "TCP"
        assert result["is_transport"] is True

    def test_threat_context_ddos(self):
        """DDoS should have MITRE ATT&CK context."""
        from app.services.enrichment_service import get_threat_context

        result = get_threat_context("DDoS")
        assert result["mitre_tactic"] == "Impact"
        assert "T1498" in result["mitre_technique"]
        assert result["recommended_action"] is not None

    def test_threat_context_benign(self):
        """BENIGN should return no threat context."""
        from app.services.enrichment_service import get_threat_context

        result = get_threat_context("BENIGN")
        assert result["mitre_tactic"] is None

    def test_threat_context_bot(self):
        """Bot should map to C&C tactic."""
        from app.services.enrichment_service import get_threat_context

        result = get_threat_context("Bot")
        assert result["mitre_tactic"] == "Command and Control"

    def test_threat_context_sql_injection(self):
        """SQL Injection should have critical severity."""
        from app.services.enrichment_service import get_threat_context

        result = get_threat_context("Web Attack - Sql Injection")
        assert result["severity_weight"] == "critical"
