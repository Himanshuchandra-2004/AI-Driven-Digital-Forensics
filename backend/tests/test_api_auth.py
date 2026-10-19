"""
Authentication API Tests.

Covers: registration, login, invalid credentials, duplicate handling,
token validation, and user profile endpoint.
"""

from __future__ import annotations

import pytest
from tests.conftest import auth_headers


@pytest.mark.asyncio
class TestRegistration:
    """Test user registration endpoint."""

    async def test_register_success(self, client):
        """Successfully register a new user."""
        response = await client.post("/api/auth/register", json={
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "SecurePass123!",
            "full_name": "New User",
        })
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "newuser"
        assert data["user"]["email"] == "newuser@test.com"
        assert data["user"]["role"] == "investigator"
        assert data["user"]["is_active"] is True

    async def test_register_duplicate_username(self, client, investigator_user):
        """Registration with existing username should fail."""
        response = await client.post("/api/auth/register", json={
            "username": "test_investigator",
            "email": "different@test.com",
            "password": "SecurePass123!",
            "full_name": "Duplicate User",
        })
        assert response.status_code == 400
        assert "already taken" in response.json()["detail"].lower()

    async def test_register_duplicate_email(self, client, investigator_user):
        """Registration with existing email should fail."""
        response = await client.post("/api/auth/register", json={
            "username": "uniqueuser",
            "email": "investigator@test.com",
            "password": "SecurePass123!",
            "full_name": "Duplicate Email",
        })
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()

    async def test_register_short_password(self, client):
        """Registration with password shorter than 8 chars should fail."""
        response = await client.post("/api/auth/register", json={
            "username": "shortpw",
            "email": "short@test.com",
            "password": "short",
            "full_name": "Short Password",
        })
        assert response.status_code == 422  # Validation error

    async def test_register_invalid_email(self, client):
        """Registration with invalid email should fail."""
        response = await client.post("/api/auth/register", json={
            "username": "bademail",
            "email": "not-an-email",
            "password": "SecurePass123!",
            "full_name": "Bad Email",
        })
        assert response.status_code == 422


@pytest.mark.asyncio
class TestLogin:
    """Test user login endpoint."""

    async def test_login_success(self, client, investigator_user):
        """Login with correct credentials."""
        response = await client.post("/api/auth/login", json={
            "username": "test_investigator",
            "password": "TestPass123!",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["username"] == "test_investigator"

    async def test_login_wrong_password(self, client, investigator_user):
        """Login with wrong password should fail."""
        response = await client.post("/api/auth/login", json={
            "username": "test_investigator",
            "password": "WrongPassword!",
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client, db_session):
        """Login with non-existent user should fail."""
        response = await client.post("/api/auth/login", json={
            "username": "ghost_user",
            "password": "AnyPassword123!",
        })
        assert response.status_code == 401

    async def test_login_case_insensitive_username(self, client, investigator_user):
        """Login should be case-insensitive for username."""
        response = await client.post("/api/auth/login", json={
            "username": "TEST_INVESTIGATOR",
            "password": "TestPass123!",
        })
        assert response.status_code == 200


@pytest.mark.asyncio
class TestCurrentUser:
    """Test /auth/me endpoint."""

    async def test_get_me_authenticated(self, client, investigator_user):
        """Authenticated user can retrieve their profile."""
        _, token = investigator_user
        response = await client.get("/api/auth/me", headers=auth_headers(token))
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "test_investigator"
        assert data["role"] == "investigator"

    async def test_get_me_no_token(self, client, db_session):
        """Request without token should fail."""
        response = await client.get("/api/auth/me")
        assert response.status_code in (401, 403)

    async def test_get_me_invalid_token(self, client, db_session):
        """Request with invalid token should fail."""
        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid-token-here"},
        )
        assert response.status_code == 401
