"""
Async SQLAlchemy engine and session management.

Supports both PostgreSQL (production) and SQLite (local development).
The engine is selected automatically based on the DATABASE_URL setting.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core import settings

# Determine if we're using SQLite
_is_sqlite = settings.async_database_url.startswith("sqlite")

_engine_kwargs = dict(
    echo=False,
    pool_pre_ping=True,
)

if not _is_sqlite:
    # PostgreSQL-specific connection pool settings
    _engine_kwargs["pool_size"] = 20
    _engine_kwargs["max_overflow"] = 10

engine = create_async_engine(
    settings.async_database_url,
    **_engine_kwargs,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency that yields a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_all_tables():
    """Create all tables (used for SQLite mode and initial setup)."""
    import app.models  # noqa: F401 — ensure all models are registered

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
