"""
app/routes/health.py — Health check and liveness probe endpoints.

These endpoints are intentionally unauthenticated and rate-limit-exempt so
that load balancers, container orchestrators (Kubernetes liveness/readiness),
and uptime monitors can poll them freely.
"""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db, mongo

health_bp = Blueprint("health", __name__, url_prefix="/health")


@health_bp.route("/live", methods=["GET"])
def liveness():
    """
    Liveness probe — the process is running.
    Returns 200 immediately. No dependency checks.
    """
    return jsonify({"status": "ok"}), 200


@health_bp.route("/ready", methods=["GET"])
def readiness():
    """
    Readiness probe — all dependencies are reachable.
    Returns 200 only if PostgreSQL and MongoDB are responsive.
    Returns 503 if any dependency is down.
    """
    checks: dict[str, str] = {}
    healthy = True

    # PostgreSQL check
    try:
        db.session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except SQLAlchemyError as exc:
        checks["postgres"] = f"error: {exc}"
        healthy = False

    # MongoDB check
    try:
        mongo.db.command("ping")
        checks["mongodb"] = "ok"
    except Exception as exc:
        checks["mongodb"] = f"error: {exc}"
        healthy = False

    status_code = 200 if healthy else 503
    return jsonify({"status": "ok" if healthy else "degraded", "checks": checks}), status_code
