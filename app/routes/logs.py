"""
app/routes/logs.py — Log retrieval Blueprint.

Exposes a paginated, filterable read API over the MongoDB audit log.
All endpoints require a valid JWT (admin-style access).
"""
from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request
from flask_jwt_extended import jwt_required

from app.extensions import limiter
from app.services.log_service import LogService

logs_bp = Blueprint("logs", __name__, url_prefix="/logs")


@logs_bp.route("/", methods=["GET"])
@jwt_required()
@limiter.limit("30 per minute")
def get_logs():
    """
    Return a paginated list of request audit log entries.

    Query parameters:
        page        (int, default 1)
        page_size   (int, default 50, max 200)
        method      (str, optional) — filter by HTTP method
        status_code (int, optional) — filter by response status code
    """
    max_page_size = current_app.config.get("MAX_PAGE_SIZE", 200)
    default_page_size = current_app.config.get("DEFAULT_PAGE_SIZE", 50)

    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(
            max_page_size,
            max(1, int(request.args.get("page_size", default_page_size))),
        )
    except ValueError:
        page, page_size = 1, default_page_size

    # Build optional filters
    filters: dict = {}
    if method := request.args.get("method", "").upper():
        filters["method"] = method
    if status_raw := request.args.get("status_code", ""):
        try:
            filters["status_code"] = int(status_raw)
        except ValueError:
            pass

    result = LogService.get_logs(page=page, page_size=page_size, filters=filters)
    return jsonify(result), 200


@logs_bp.route("/<string:log_id>", methods=["GET"])
@jwt_required()
@limiter.limit("60 per minute")
def get_log_detail(log_id: str):
    """
    Return the full detail of a single log entry by its MongoDB ObjectId.

    Path parameter:
        log_id  — 24-char hex MongoDB ObjectId string
    """
    result = LogService.get_log_by_id(log_id)
    return jsonify(result), 200
