"""
app/routes/protected.py — Example of a JWT-protected resource endpoint.

Demonstrates the full auth flow: JWT validation → identity extraction → response.
"""
from __future__ import annotations

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.extensions import limiter

protected_bp = Blueprint("protected", __name__, url_prefix="/api")


@protected_bp.route("/me", methods=["GET"])
@jwt_required()
@limiter.limit("60 per minute")
def get_current_user():
    """
    Return the identity of the currently authenticated user.

    Requires: Authorization: Bearer <access_token>
    """
    identity = get_jwt_identity()
    return jsonify({"user": identity}), 200


@protected_bp.route("/ping", methods=["GET"])
@jwt_required()
@limiter.limit("100 per minute")
def ping():
    """Simple authenticated ping endpoint for smoke-testing token validity."""
    return jsonify({"message": "pong", "authenticated": True}), 200
