"""
AI-Driven Digital Forensics — Network Forensics
FastAPI Application Entry Point

Registers all routers, CORS, middleware, error handlers, and startup events.
Production-quality configuration with structured logging and observability.
"""

from __future__ import annotations

import logging
import platform
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core import settings

# ---- Structured Logging Configuration ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("forensics.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    # Startup banner
    logger.info("=" * 60)
    logger.info("  AI-Driven Digital Forensics — Network Forensics v1.0.0")
    logger.info("  Python %s on %s", platform.python_version(), platform.system())
    logger.info("  Database: %s", "SQLite" if settings.USE_SQLITE else "PostgreSQL")
    logger.info("  ML Models: %s", settings.MODEL_DIR)
    logger.info("=" * 60)

    # Startup: ensure upload and reports directories exist
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    settings.reports_path.mkdir(parents=True, exist_ok=True)

    # Auto-create tables when using SQLite (no Alembic needed)
    if settings.USE_SQLITE:
        from app.core.database import create_all_tables
        await create_all_tables()
        logger.info("Database tables verified (SQLite)")

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Application shutting down")


app = FastAPI(
    title="AI-Driven Digital Forensics — Network Forensics",
    description=(
        "An integrated AI-driven network-forensics framework combining "
        "Isolation Forest anomaly detection, Random Forest threat classification, "
        "evidence correlation, secure evidence handling, chain of custody, "
        "and automated forensic reporting."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ---- Register Error Handlers ----
from app.core.error_handlers import register_error_handlers  # noqa: E402

register_error_handlers(app)

# ---- Register Middleware ----
from app.core.middleware import register_middleware  # noqa: E402

register_middleware(app)

# ---- CORS (must be after custom middleware registration) ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Register API Routers ----
from app.api.auth import router as auth_router  # noqa: E402
from app.api.cases import router as cases_router  # noqa: E402
from app.api.analysis import router as analysis_router  # noqa: E402
from app.api.evidence import router as evidence_router  # noqa: E402
from app.api.incidents import router as incidents_router  # noqa: E402
from app.api.reports import router as reports_router  # noqa: E402
from app.api.models_api import router as models_router  # noqa: E402
from app.api.dashboard import router as dashboard_router  # noqa: E402
from app.api.demo import router as demo_router  # noqa: E402
from app.api.system import router as system_router  # noqa: E402
from app.api.timeline import router as timeline_router  # noqa: E402

app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(cases_router, prefix="/api/cases", tags=["Cases"])
app.include_router(analysis_router, prefix="/api", tags=["Analysis"])
app.include_router(evidence_router, prefix="/api", tags=["Evidence"])
app.include_router(incidents_router, prefix="/api", tags=["Incidents"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])
app.include_router(models_router, prefix="/api/models", tags=["Models"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(demo_router, prefix="/api/demo", tags=["Demo"])
app.include_router(system_router, prefix="/api/system", tags=["System"])
app.include_router(timeline_router, prefix="/api", tags=["Timeline & Analysis"])


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Lightweight health check endpoint (no auth required)."""
    return {
        "status": "healthy",
        "service": "AI-Driven Digital Forensics",
        "version": "1.0.0",
    }
