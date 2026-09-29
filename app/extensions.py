"""
app/extensions.py — Flask extension singletons.

Extensions are instantiated here (without an app) and initialised inside
create_app() via the init_app() pattern. A single Limiter instance is used
(Flask-Limiter is not designed for multiple instances) with per-route
overrides applied via decorators.
"""
from __future__ import annotations

from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_pymongo import PyMongo
from flask_sqlalchemy import SQLAlchemy

# ── Core data stores ─────────────────────────────────────────────────────────
db = SQLAlchemy()
migrate = Migrate()
mongo = PyMongo()

# ── Auth ─────────────────────────────────────────────────────────────────────
jwt = JWTManager()


def _rate_limit_key() -> str:
    """
    Rate-limit key: prefer authenticated user identity (prevents key-sharing
    among users behind the same NAT/proxy); fall back to remote IP for
    anonymous requests.
    """
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            return f"user:{identity}"
    except Exception:
        pass
    return get_remote_address()


# ── Single Limiter instance ───────────────────────────────────────────────────
# Per-route overrides are applied with @limiter.limit("X/Y") decorators.
# RATELIMIT_STORAGE_URI and RATELIMIT_DEFAULT are loaded from app.config.
limiter = Limiter(
    key_func=_rate_limit_key,
    default_limits=["200 per day", "50 per hour"],
)