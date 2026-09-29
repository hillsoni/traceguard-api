"""
app/exceptions.py — Custom exception hierarchy.

All domain exceptions inherit from AppError, which carries a structured
JSON-serialisable payload. The application factory registers a single
centralised handler for AppError subclasses, keeping error logic out of
views and services.
"""
from __future__ import annotations

from http import HTTPStatus


class AppError(Exception):
    """
    Base class for all application-level errors.

    Attributes:
        message:    Human-readable description shown to the API consumer.
        status:     HTTP status code to return.
        code:       Machine-readable error code for programmatic handling.
        details:    Optional extra context (never include raw secrets/PII).
    """

    status: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str = "An unexpected error occurred.",
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self, request_id: str | None = None) -> dict:
        payload: dict = {
            "error": self.code,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        if request_id:
            payload["request_id"] = request_id
        return payload


# ── 400 Bad Request ───────────────────────────────────────────────────────────

class ValidationError(AppError):
    """Raised when incoming request data fails schema or business validation."""
    status = HTTPStatus.BAD_REQUEST
    code = "VALIDATION_ERROR"


class BadRequestError(AppError):
    """Generic malformed request (unparsable JSON, missing body, etc.)."""
    status = HTTPStatus.BAD_REQUEST
    code = "BAD_REQUEST"


# ── 401 Unauthorized ─────────────────────────────────────────────────────────

class AuthenticationError(AppError):
    """Invalid credentials or expired/revoked token."""
    status = HTTPStatus.UNAUTHORIZED
    code = "AUTHENTICATION_ERROR"


# ── 403 Forbidden ────────────────────────────────────────────────────────────

class AuthorizationError(AppError):
    """Valid token but insufficient permissions."""
    status = HTTPStatus.FORBIDDEN
    code = "AUTHORIZATION_ERROR"


# ── 404 Not Found ────────────────────────────────────────────────────────────

class NotFoundError(AppError):
    """Requested resource does not exist."""
    status = HTTPStatus.NOT_FOUND
    code = "NOT_FOUND"


# ── 409 Conflict ─────────────────────────────────────────────────────────────

class ConflictError(AppError):
    """Resource already exists (e.g., duplicate email on registration)."""
    status = HTTPStatus.CONFLICT
    code = "CONFLICT"


# ── 422 Unprocessable Entity ─────────────────────────────────────────────────

class UnprocessableError(AppError):
    """Request is structurally valid JSON but semantically invalid."""
    status = HTTPStatus.UNPROCESSABLE_ENTITY
    code = "UNPROCESSABLE_ENTITY"


# ── 429 Too Many Requests ────────────────────────────────────────────────────

class RateLimitError(AppError):
    """Client has exceeded the configured rate limit."""
    status = HTTPStatus.TOO_MANY_REQUESTS
    code = "RATE_LIMIT_EXCEEDED"


# ── 500 Internal Server Error ────────────────────────────────────────────────

class DatabaseError(AppError):
    """Wraps unexpected database-layer failures."""
    status = HTTPStatus.INTERNAL_SERVER_ERROR
    code = "DATABASE_ERROR"


class ServiceUnavailableError(AppError):
    """Downstream dependency (DB, cache, etc.) is unreachable."""
    status = HTTPStatus.SERVICE_UNAVAILABLE
    code = "SERVICE_UNAVAILABLE"
