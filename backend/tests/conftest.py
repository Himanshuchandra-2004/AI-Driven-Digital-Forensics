"""
Shared test fixtures for the Digital Forensics backend test suite.

Provides:
- In-memory SQLite test database
- Async test client
- Authenticated user fixtures (investigator, admin, viewer)
- Sample case and evidence fixtures
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app


# ---- Test Database ----

TEST_DATABASE_URL = "sqlite+aiosqlite://"  # In-memory

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
test_session_factory = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


async def _get_test_db():
    """Override get_db to use the test database."""
    async with test_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Override the DB dependency
app.dependency_overrides[get_db] = _get_test_db


# ---- Fixtures ----

@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Create tables and yield a test session, then drop tables."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with test_session_factory() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    """Async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(scope="function")
async def investigator_user(db_session):
    """Create an investigator user and return (user, token)."""
    from app.models.user import User

    user = User(
        username="test_investigator",
        email="investigator@test.com",
        password_hash=hash_password("TestPass123!"),
        full_name="Test Investigator",
        role="investigator",
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return user, token


@pytest_asyncio.fixture(scope="function")
async def admin_user(db_session):
    """Create an admin user and return (user, token)."""
    from app.models.user import User

    user = User(
        username="test_admin",
        email="admin@test.com",
        password_hash=hash_password("AdminPass123!"),
        full_name="Test Admin",
        role="admin",
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return user, token


@pytest_asyncio.fixture(scope="function")
async def viewer_user(db_session):
    """Create a viewer user and return (user, token)."""
    from app.models.user import User

    user = User(
        username="test_viewer",
        email="viewer@test.com",
        password_hash=hash_password("ViewerPass123!"),
        full_name="Test Viewer",
        role="viewer",
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return user, token


@pytest_asyncio.fixture(scope="function")
async def sample_case(db_session, investigator_user):
    """Create a sample case owned by the investigator."""
    from app.models.case import Case

    user, _ = investigator_user
    case = Case(
        user_id=user.id,
        name="Test Case — Network Intrusion Analysis",
        description="A test case for automated testing of the forensics platform.",
        status="open",
    )
    db_session.add(case)
    await db_session.flush()
    await db_session.refresh(case)
    return case


def auth_headers(token: str) -> dict:
    """Build auth headers from a JWT token."""
    return {"Authorization": f"Bearer {token}"}
