"""
Cases API Tests.

Covers: CRUD operations, access control, file upload validation.
"""

from __future__ import annotations

import pytest
from tests.conftest import auth_headers


@pytest.mark.asyncio
class TestCasesCRUD:
    """Test case creation, reading, updating, and deletion."""

    async def test_create_case(self, client, investigator_user):
        """Investigator can create a new case."""
        _, token = investigator_user
        response = await client.post(
            "/api/cases",
            json={
                "name": "Suspicious Network Activity Investigation",
                "description": "Investigating anomalous outbound traffic patterns.",
            },
            headers=auth_headers(token),
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Suspicious Network Activity Investigation"
        assert data["status"] == "open"
        assert data["evidence_count"] == 0
        assert "id" in data

    async def test_list_cases(self, client, investigator_user, sample_case):
        """User can list their cases."""
        _, token = investigator_user
        response = await client.get("/api/cases", headers=auth_headers(token))
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(c["name"] == sample_case.name for c in data)

    async def test_get_case_by_id(self, client, investigator_user, sample_case):
        """Get a specific case by ID."""
        _, token = investigator_user
        response = await client.get(
            f"/api/cases/{sample_case.id}",
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == sample_case.name

    async def test_update_case(self, client, investigator_user, sample_case):
        """Investigator can update their case."""
        _, token = investigator_user
        response = await client.put(
            f"/api/cases/{sample_case.id}",
            json={"name": "Updated Case Name", "status": "closed"},
            headers=auth_headers(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Case Name"
        assert data["status"] == "closed"

    async def test_create_case_empty_name(self, client, investigator_user):
        """Creating a case with empty name should fail."""
        _, token = investigator_user
        response = await client.post(
            "/api/cases",
            json={"name": "", "description": "No name"},
            headers=auth_headers(token),
        )
        assert response.status_code == 422


@pytest.mark.asyncio
class TestCasesAccessControl:
    """Test role-based access control for cases."""

    async def test_viewer_cannot_create_case(self, client, viewer_user):
        """Viewer role should not be able to create cases."""
        _, token = viewer_user
        response = await client.post(
            "/api/cases",
            json={"name": "Unauthorized Case", "description": "Should fail"},
            headers=auth_headers(token),
        )
        assert response.status_code == 403

    async def test_viewer_can_list_cases(self, client, viewer_user):
        """Viewer role can list cases (read access)."""
        _, token = viewer_user
        response = await client.get("/api/cases", headers=auth_headers(token))
        assert response.status_code == 200

    async def test_no_auth_cannot_access(self, client, db_session):
        """Unauthenticated requests should fail."""
        response = await client.get("/api/cases")
        assert response.status_code in (401, 403)

    async def test_case_not_found(self, client, investigator_user):
        """Accessing non-existent case returns 404."""
        _, token = investigator_user
        import uuid
        response = await client.get(
            f"/api/cases/{uuid.uuid4()}",
            headers=auth_headers(token),
        )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestCasesFileUpload:
    """Test file upload validation."""

    async def test_upload_rejected_without_file(self, client, investigator_user, sample_case):
        """Upload endpoint requires a file."""
        _, token = investigator_user
        response = await client.post(
            f"/api/cases/{sample_case.id}/upload",
            headers=auth_headers(token),
        )
        assert response.status_code == 422
