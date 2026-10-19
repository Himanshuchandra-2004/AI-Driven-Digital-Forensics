"""
Application configuration loaded from environment variables.
Uses pydantic-settings for validation and type coercion.

Supports both PostgreSQL (production) and SQLite (local development).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration — all values come from env vars or .env file."""

    # ---- Database ----
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "forensics_db"
    POSTGRES_USER: str = "forensics_user"
    POSTGRES_PASSWORD: str = "forensics_pass"
    DATABASE_URL: str = ""
    DATABASE_URL_SYNC: str = ""

    # ---- SQLite fallback (local dev) ----
    USE_SQLITE: bool = True  # Default to SQLite for easy local development

    # ---- JWT ----
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # ---- CORS ----
    CORS_ORIGINS: str = '["http://localhost:5173","http://localhost:3000"]'

    # ---- Upload ----
    MAX_UPLOAD_SIZE_MB: int = 100
    UPLOAD_DIR: str = "uploads"

    # ---- ML ----
    MODEL_DIR: str = "../ml/models"
    DEMO_DATA_RECORDS: int = 5000

    class Config:
        env_file = ".env"
        extra = "allow"

    @property
    def async_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        if self.USE_SQLITE:
            db_path = Path(__file__).parent.parent.parent / "forensics.db"
            return f"sqlite+aiosqlite:///{db_path}"
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        if self.DATABASE_URL_SYNC:
            return self.DATABASE_URL_SYNC
        if self.USE_SQLITE:
            db_path = Path(__file__).parent.parent.parent / "forensics.db"
            return f"sqlite:///{db_path}"
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def cors_origins_list(self) -> List[str]:
        try:
            return json.loads(self.CORS_ORIGINS)
        except (json.JSONDecodeError, TypeError):
            return ["http://localhost:5173"]

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def reports_path(self) -> Path:
        p = Path("reports")
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def model_path(self) -> Path:
        return Path(self.MODEL_DIR)


settings = Settings()
