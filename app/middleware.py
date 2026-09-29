"""
app/middleware.py — Request lifecycle middleware.

Responsibilities:
  1. Generate a unique request_id (X-Request-ID) for distributed tracing.
  2. Emit a structured JSON log line for every request/response (replaces
     the inline before/after_request in the old __init__.py).
  3. Inject security headers on every response (fixes H-1).
  4. Expose request_id to the rest of the application via flask.g.
"""
from __future__ import annotations

import logging
import time
import uuid

from flask import Flask, g, request, Response

logger = logging.getLogger(__name__)


def register_middleware(app: Flask) -> None:
    """Attach all middleware hooks to the application."""

    @app.before_request
    def _start_timer() -> None:
        """Record start time and attach a unique request_id."""
        g.start_time = time.perf_counter()
        # Honour an upstream correlation header, or generate a fresh UUID
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    @app.after_request
    def _add_security_headers(response: Response) -> Response:
        """
        Inject security headers on every response (fixes H-1).
        These are intentionally conservative defaults suitable for an API;
        adjust CSP if you later serve HTML.
        """
        duration_ms = round(
            (time.perf_counter() - g.get("start_time", time.perf_counter())) * 1000, 2
        )

        # ── Security headers ─────────────────────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["Cache-Control"] = "no-store"
        # Propagate correlation ID back to the caller
        response.headers["X-Request-ID"] = g.get("request_id", "")
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        # ── Structured access log ────────────────────────────────────────────
        logger.info(
            "request_completed",
            extra={
                "request_id": g.get("request_id"),
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "remote_addr": request.remote_addr,
            },
        )

        return response
