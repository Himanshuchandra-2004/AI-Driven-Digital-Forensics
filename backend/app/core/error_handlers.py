"""
Structured error handling for the Digital Forensics platform.

Provides:
- Custom exception hierarchy for forensics-specific errors
- Global exception handlers that return structured JSON responses
- Consistent error response format across all endpoints

Error Response Format:
{
    "error_code": "EVIDENCE_INTEGRITY_ERROR",
    "detail": "Evidence hash mismatch detected",
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req-abc123",
    "path": "/api/evidence/123/verify"
}
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("forensics.errors")


# ---- Custom Exception Hierarchy ----

class ForensicsException(Exception):
    """Base exception for all forensics platform errors."""

    def __init__(
        self,
        detail: str,
        error_code: str = "FORENSICS_ERROR",
        status_code: int = 500,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.detail = detail
        self.error_code = error_code
        self.status_code = status_code
        self.extra = extra or {}
        super().__init__(detail)


class EvidenceIntegrityError(ForensicsException):
    """Raised when evidence integrity verification fails."""

    def __init__(self, detail: str, evidence_id: Optional[str] = None):
        super().__init__(
            detail=detail,
            error_code="EVIDENCE_INTEGRITY_ERROR",
            status_code=422,
            extra={"evidence_id": evidence_id} if evidence_id else {},
        )


class AnalysisError(ForensicsException):
    """Raised when an analysis pipeline operation fails."""

    def __init__(self, detail: str, analysis_run_id: Optional[str] = None):
        super().__init__(
            detail=detail,
            error_code="ANALYSIS_ERROR",
            status_code=500,
            extra={"analysis_run_id": analysis_run_id} if analysis_run_id else {},
        )


class ModelNotLoadedError(ForensicsException):
    """Raised when ML models are not available."""

    def __init__(self, detail: str = "ML models not loaded or unavailable"):
        super().__init__(
            detail=detail,
            error_code="MODEL_NOT_LOADED",
            status_code=503,
        )


class AuthorizationError(ForensicsException):
    """Raised for role-based access control violations."""

    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            detail=detail,
            error_code="AUTHORIZATION_ERROR",
            status_code=403,
        )


class ResourceNotFoundError(ForensicsException):
    """Raised when a requested resource doesn't exist."""

    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            detail=f"{resource_type} not found: {resource_id}",
            error_code="RESOURCE_NOT_FOUND",
            status_code=404,
            extra={"resource_type": resource_type, "resource_id": resource_id},
        )


class RateLimitExceededError(ForensicsException):
    """Raised when a client exceeds the rate limit."""

    def __init__(self, detail: str = "Rate limit exceeded. Try again later."):
        super().__init__(
            detail=detail,
            error_code="RATE_LIMIT_EXCEEDED",
            status_code=429,
        )


class FileValidationError(ForensicsException):
    """Raised for invalid file uploads."""

    def __init__(self, detail: str):
        super().__init__(
            detail=detail,
            error_code="FILE_VALIDATION_ERROR",
            status_code=400,
        )


# ---- Structured Error Response Builder ----

def _build_error_response(
    request: Request,
    status_code: int,
    error_code: str,
    detail: str,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """Build a structured JSON error response."""
    request_id = getattr(request.state, "request_id", "unknown")
    body = {
        "error_code": error_code,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "path": str(request.url.path),
    }
    if extra:
        body["meta"] = extra

    return JSONResponse(status_code=status_code, content=body)


# ---- Exception Handlers ----

async def forensics_exception_handler(
    request: Request, exc: ForensicsException
) -> JSONResponse:
    """Handle custom ForensicsException and subclasses."""
    logger.warning(
        "ForensicsException: %s [%s] path=%s",
        exc.error_code,
        exc.detail,
        request.url.path,
    )
    return _build_error_response(
        request,
        status_code=exc.status_code,
        error_code=exc.error_code,
        detail=exc.detail,
        extra=exc.extra if exc.extra else None,
    )


async def http_exception_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    """Override FastAPI's default HTTPException handler for structured output."""
    error_code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        413: "PAYLOAD_TOO_LARGE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
    }
    error_code = error_code_map.get(exc.status_code, "HTTP_ERROR")
    return _build_error_response(
        request,
        status_code=exc.status_code,
        error_code=error_code,
        detail=str(exc.detail),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle Pydantic/FastAPI request validation errors."""
    from fastapi.exceptions import RequestValidationError

    if isinstance(exc, RequestValidationError):
        errors = exc.errors()
        detail = "; ".join(
            f"{'.'.join(str(loc) for loc in e.get('loc', []))}: {e.get('msg', '')}"
            for e in errors
        )
        return _build_error_response(
            request,
            status_code=422,
            error_code="VALIDATION_ERROR",
            detail=detail,
            extra={"validation_errors": errors},
        )
    return _build_error_response(
        request,
        status_code=422,
        error_code="VALIDATION_ERROR",
        detail=str(exc),
    )


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Catch-all for unhandled exceptions — log full traceback, return safe response."""
    logger.error(
        "Unhandled exception on %s %s: %s\n%s",
        request.method,
        request.url.path,
        str(exc),
        traceback.format_exc(),
    )
    return _build_error_response(
        request,
        status_code=500,
        error_code="INTERNAL_SERVER_ERROR",
        detail="An unexpected error occurred. Please contact the administrator.",
    )


# ---- Registration ----

def register_error_handlers(app: FastAPI) -> None:
    """Register all exception handlers with the FastAPI app."""
    from fastapi.exceptions import RequestValidationError

    app.add_exception_handler(ForensicsException, forensics_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
