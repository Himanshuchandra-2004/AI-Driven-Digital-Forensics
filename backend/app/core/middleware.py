"""
Production middleware for the Digital Forensics platform.

Provides:
1. Request ID injection — unique ID per request for traceability
2. Structured request/response logging — timing, status, user attribution
3. Rate limiting — in-memory token bucket for auth endpoints
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Tuple

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger("forensics.middleware")

# ---- In-Memory Audit Log ----
# Stores recent requests for the /api/system/audit-log endpoint
_audit_log: List[Dict] = []
_MAX_AUDIT_LOG_SIZE = 500


def get_audit_log() -> List[Dict]:
    """Return the in-memory audit log (most recent first)."""
    return list(reversed(_audit_log))


# ---- In-Memory Metrics ----
_metrics = {
    "total_requests": 0,
    "total_errors": 0,
    "status_codes": defaultdict(int),
    "response_times": [],  # Last N response times in ms
    "started_at": datetime.now(timezone.utc).isoformat(),
}
_MAX_RESPONSE_TIMES = 1000


def get_metrics() -> Dict:
    """Return aggregated request metrics."""
    response_times = _metrics["response_times"]
    avg_response = (
        round(sum(response_times) / len(response_times), 2)
        if response_times
        else 0.0
    )
    p95 = (
        round(sorted(response_times)[int(len(response_times) * 0.95)], 2)
        if len(response_times) > 20
        else avg_response
    )
    return {
        "total_requests": _metrics["total_requests"],
        "total_errors": _metrics["total_errors"],
        "status_code_distribution": dict(_metrics["status_codes"]),
        "avg_response_time_ms": avg_response,
        "p95_response_time_ms": p95,
        "uptime_since": _metrics["started_at"],
    }


# ---- Request ID Middleware ----

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Inject a unique X-Request-ID into every request/response.
    
    If the client provides X-Request-ID, it is preserved.
    Otherwise, a new UUID is generated.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---- Request Logging Middleware ----

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log every request with method, path, status, timing, and user info.
    Also records metrics and audit log entries.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start_time = time.time()

        response = await call_next(request)

        duration_ms = round((time.time() - start_time) * 1000, 2)
        status_code = response.status_code
        request_id = getattr(request.state, "request_id", "unknown")

        # Update metrics
        _metrics["total_requests"] += 1
        _metrics["status_codes"][status_code] += 1
        if status_code >= 400:
            _metrics["total_errors"] += 1
        _metrics["response_times"].append(duration_ms)
        if len(_metrics["response_times"]) > _MAX_RESPONSE_TIMES:
            _metrics["response_times"] = _metrics["response_times"][-_MAX_RESPONSE_TIMES:]

        # Log for non-static requests
        path = request.url.path
        if not path.startswith("/docs") and not path.startswith("/openapi"):
            log_level = logging.WARNING if status_code >= 400 else logging.INFO
            logger.log(
                log_level,
                "%s %s → %d (%sms) [%s]",
                request.method,
                path,
                status_code,
                duration_ms,
                request_id,
            )

            # Audit log entry
            _audit_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "request_id": request_id,
                "client_ip": request.client.host if request.client else "unknown",
            })
            if len(_audit_log) > _MAX_AUDIT_LOG_SIZE:
                _audit_log.pop(0)

        # Add timing header
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        return response


# ---- Rate Limiting Middleware ----

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token bucket rate limiter for sensitive endpoints (auth).
    
    - Auth endpoints: 10 requests per minute per IP
    - General API: 120 requests per minute per IP
    """

    def __init__(self, app, auth_rpm: int = 10, general_rpm: int = 120):
        super().__init__(app)
        self.auth_rpm = auth_rpm
        self.general_rpm = general_rpm
        self._buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_refill)

    def _get_tokens(self, key: str, rpm: int) -> float:
        """Get current token count, refilling based on elapsed time."""
        now = time.time()
        if key not in self._buckets:
            self._buckets[key] = (float(rpm), now)
            return float(rpm)

        tokens, last_refill = self._buckets[key]
        elapsed = now - last_refill
        refill = elapsed * (rpm / 60.0)
        tokens = min(float(rpm), tokens + refill)
        self._buckets[key] = (tokens, now)
        return tokens

    def _consume(self, key: str, rpm: int) -> bool:
        """Try to consume a token. Returns True if allowed."""
        tokens = self._get_tokens(key, rpm)
        if tokens >= 1.0:
            now = time.time()
            self._buckets[key] = (tokens - 1.0, now)
            return True
        return False

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Apply stricter limits to auth endpoints
        if "/auth/" in path and request.method == "POST":
            key = f"auth:{client_ip}"
            if not self._consume(key, self.auth_rpm):
                from app.core.error_handlers import RateLimitExceededError
                logger.warning("Rate limit exceeded for %s on %s", client_ip, path)
                return Response(
                    content='{"error_code":"RATE_LIMIT_EXCEEDED","detail":"Too many authentication attempts. Try again later."}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "60"},
                )
        else:
            key = f"api:{client_ip}"
            if not self._consume(key, self.general_rpm):
                return Response(
                    content='{"error_code":"RATE_LIMIT_EXCEEDED","detail":"Rate limit exceeded. Try again later."}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "30"},
                )

        return await call_next(request)


# ---- Registration ----

def register_middleware(app: FastAPI) -> None:
    """Register all middleware with the FastAPI app (order matters: last added = outermost)."""
    # Rate limiting (outermost — runs first)
    app.add_middleware(RateLimitMiddleware)
    # Request logging (runs after rate limit)
    app.add_middleware(RequestLoggingMiddleware)
    # Request ID injection (innermost — runs last, ensures ID exists for logging)
    app.add_middleware(RequestIDMiddleware)
