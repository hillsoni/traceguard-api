"""
app/__init__.py — Application factory.

Follows the Flask Application Factory pattern so that create_app() can be
called with different configs (testing, development, production) without
creating global state at import time.

All extensions, middleware, blueprints, and error handlers are registered
here. No business logic lives in this file.
"""
from __future__ import annotations

import logging
from typing import Type

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import get_jwt, get_jwt_identity
from flask_limiter.errors import RateLimitExceeded

from app.config import BaseConfig, get_config
from app.exceptions import AppError
from app.extensions import db, jwt, limiter, migrate, mongo
from app.logging_config import configure_logging
from app.middleware import register_middleware
from app.services.log_service import LogService

logger = logging.getLogger(__name__)


def create_app(config_class: Type[BaseConfig] | None = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_class: Configuration class to use. If None, auto-selects
                      based on the FLASK_ENV environment variable.

    Returns:
        A fully initialised Flask application instance.
    """
    if config_class is None:
        config_class = get_config()

    # Validate required secrets before constructing anything
    if hasattr(config_class, "validate"):
        config_class.validate()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # ── Structured logging (must be first so all subsequent logs are JSON) ────
    configure_logging(app.config.get("LOG_LEVEL", "INFO"))

    # ── Extensions ───────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    mongo.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS(
        app,
        origins=app.config.get("CORS_ORIGINS", []),
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Response-Time-Ms", "X-RateLimit-Limit"],
        max_age=3600,
    )

    # ── Middleware (request ID, security headers, access logging) ─────────────
    register_middleware(app)

    # ── Request-lifecycle audit logging ───────────────────────────────────────
    _register_audit_hooks(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    _register_blueprints(app)

    # ── JWT error handlers ────────────────────────────────────────────────────
    _register_jwt_handlers(app)

    # ── Centralised error handlers ────────────────────────────────────────────
    _register_error_handlers(app)

    logger.info(
        "application_started",
        extra={
            "env": app.config.get("ENV", "unknown"),
            "debug": app.debug,
        },
    )

    return app


# ── Private helpers ───────────────────────────────────────────────────────────

def _register_blueprints(app: Flask) -> None:
    from app.routes.auth import auth_bp
    from app.routes.health import health_bp
    from app.routes.logs import logs_bp
    from app.routes.protected import protected_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(protected_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(health_bp)


def _register_audit_hooks(app: Flask) -> None:
    """
    Persist request/response data to MongoDB for every request.
    Logging is best-effort: failures are recorded but never abort the request.
    """

    @app.before_request
    def _log_incoming_request() -> None:
        g.log_id = LogService.capture_request()

    @app.after_request
    def _log_outgoing_response(response):
        LogService.capture_response(g.get("log_id"), response)
        return response

    @app.teardown_request
    def _log_exception(exception: BaseException | None) -> None:
        if exception:
            LogService.capture_exception(g.get("log_id", ""), exception)


def _register_jwt_handlers(app: Flask) -> None:
    """
    Register JWT error callbacks.  All return the same envelope structure
    as _register_error_handlers() for a consistent API surface.
    """
    from app.extensions import jwt as _jwt

    @_jwt.revoked_token_loader
    def revoked_token(_header, _payload):
        return jsonify({"error": "TOKEN_REVOKED", "message": "Token has been revoked."}), 401

    @_jwt.expired_token_loader
    def expired_token(_header, _payload):
        return jsonify({"error": "TOKEN_EXPIRED", "message": "Token has expired. Please refresh."}), 401

    @_jwt.invalid_token_loader
    def invalid_token(reason: str):
        return jsonify({"error": "TOKEN_INVALID", "message": f"Token is invalid: {reason}"}), 401

    @_jwt.unauthorized_loader
    def missing_token(reason: str):
        return jsonify({"error": "AUTHORIZATION_REQUIRED", "message": "No token provided."}), 401


def _register_error_handlers(app: Flask) -> None:
    """
    Centralised, standardised JSON error responses.
    All handlers use the same envelope format.
    """

    @app.errorhandler(AppError)
    def handle_app_error(exc: AppError):
        """Single handler for all domain exceptions (replaces scattered handlers)."""
        logger.warning(
            "app_error",
            extra={
                "code": exc.code,
                "status": exc.status,
                "message": exc.message,
                "request_id": g.get("request_id"),
            },
        )
        return jsonify(exc.to_dict(request_id=g.get("request_id"))), exc.status

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(exc: RateLimitExceeded):
        return jsonify({
            "error": "RATE_LIMIT_EXCEEDED",
            "message": str(exc.description),
            "request_id": g.get("request_id"),
        }), 429

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({
            "error": "NOT_FOUND",
            "message": "The requested endpoint does not exist.",
            "request_id": g.get("request_id"),
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({
            "error": "METHOD_NOT_ALLOWED",
            "message": "HTTP method not allowed for this endpoint.",
            "request_id": g.get("request_id"),
        }), 405

    @app.errorhandler(500)
    def internal_error(exc: Exception):
        logger.error(
            "unhandled_exception",
            extra={"request_id": g.get("request_id")},
            exc_info=exc,
        )
        return jsonify({
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred.",
            "request_id": g.get("request_id"),
        }), 500