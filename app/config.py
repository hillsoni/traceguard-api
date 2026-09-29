"""
config.py — Environment-driven configuration.

Uses python-dotenv for .env loading. Fails fast at startup if required
secrets are absent, preventing silent misconfiguration in production.
"""
from __future__ import annotations

import os
import secrets
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


def _require_env(key: str) -> str:
    """Raise at import-time if a required environment variable is missing."""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(
            f"Required environment variable '{key}' is not set. "
            f"See .env.example for a reference."
        )
    return value


class BaseConfig:
    """Shared defaults for all environments."""

    # ── Application ──────────────────────────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    APP_NAME: str = os.getenv("APP_NAME", "TraceGuard API")

    # ── SQLAlchemy (PostgreSQL) ───────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.getenv("DB_URL", "")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,        # Recycle stale connections
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
        "pool_recycle": 1800,         # Recycle connections every 30 min
    }

    # ── MongoDB ───────────────────────────────────────────────────────────────
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/flaskdb")

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(days=7)
    JWT_TOKEN_LOCATION: list[str] = ["headers"]
    JWT_HEADER_NAME: str = "Authorization"
    JWT_HEADER_TYPE: str = "Bearer"
    JWT_ERROR_MESSAGE_KEY: str = "error"

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URI: str = os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    )
    RATELIMIT_DEFAULT: list[str] = ["200 per day", "50 per hour"]
    RATELIMIT_STRATEGY: str = "fixed-window-elastic-expiry"
    RATELIMIT_HEADERS_ENABLED: bool = True   # Return X-RateLimit-* headers

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000"
    ).split(",")

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Pagination ────────────────────────────────────────────────────────────
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 200


class DevelopmentConfig(BaseConfig):
    """Local development settings — verbose, relaxed limits."""

    DEBUG: bool = True
    TESTING: bool = False
    LOG_LEVEL: str = "DEBUG"
    SQLALCHEMY_ECHO: bool = True   # Log all SQL statements
    RATELIMIT_DEFAULT: list[str] = ["10000 per day"]
    CORS_ORIGINS: list[str] = ["*"]


class TestingConfig(BaseConfig):
    """In-memory databases for fast, isolated unit/integration tests."""

    DEBUG: bool = False
    TESTING: bool = True
    WTF_CSRF_ENABLED: bool = False

    # Use SQLite in-memory so tests don't require a running database
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    MONGO_URI: str = "mongomock://localhost/test_flaskdb"

    JWT_SECRET_KEY: str = "test-only-jwt-secret-not-for-production"
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(minutes=5)

    # Disable rate limiting in tests
    RATELIMIT_ENABLED: bool = False


class ProductionConfig(BaseConfig):
    """Hardened production settings. Fails fast if secrets are absent."""

    DEBUG: bool = False
    TESTING: bool = False
    LOG_LEVEL: str = "WARNING"

    # ── Require real secrets in production ────────────────────────────────────
    @classmethod
    def validate(cls) -> None:
        """
        Call during create_app() to assert all required secrets are present.
        Raises RuntimeError early rather than allowing a partially-configured
        production service.
        """
        required = [
            "JWT_SECRET_KEY",
            "DB_URL",
            "MONGO_URI",
            "SECRET_KEY",
        ]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            raise RuntimeError(
                f"[PRODUCTION] Required environment variables are not set: "
                f"{', '.join(missing)}"
            )

    # Tighten JWT lifetime in production
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(days=7)


# ── Config registry ──────────────────────────────────────────────────────────

_CONFIG_MAP: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config() -> type[BaseConfig]:
    """
    Return the appropriate config class based on the FLASK_ENV environment
    variable. Defaults to DevelopmentConfig if not set.
    """
    env = os.getenv("FLASK_ENV", "development").lower()
    return _CONFIG_MAP.get(env, DevelopmentConfig)
