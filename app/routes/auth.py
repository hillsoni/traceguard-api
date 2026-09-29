"""
app/routes/auth.py — Authentication Blueprint (thin controller).

Responsibilities:
  - Parse HTTP request body into a schema object.
  - Call the service layer.
  - Serialise the result into a JSON HTTP response.

No business logic lives here. All validation errors surface as
ValidationError/ConflictError and are handled by the centralised
error handler registered in create_app().
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from app.extensions import limiter
from app.schemas.auth import LoginSchema, RegisterSchema
from app.services.auth_service import AuthService

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per hour")          # Tighter limit on account creation
def register():
    """
    Register a new user account.

    Request body (JSON):
        email, username, password, confirm

    Returns 201 with access_token + refresh_token on success.
    """
    schema = RegisterSchema.from_dict(request.get_json(silent=True))
    result = AuthService.register(schema)
    return jsonify(result), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per hour")
def login():
    """
    Authenticate with email + password.

    Returns 200 with access_token + refresh_token on success.
    """
    schema = LoginSchema.from_dict(request.get_json(silent=True))
    result = AuthService.login(schema)
    return jsonify(result), 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Exchange a valid refresh token for a new access token.

    Requires: Authorization: Bearer <refresh_token>
    """
    current_user = get_jwt_identity()
    result = AuthService.refresh(current_user)
    return jsonify(result), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Revoke the current access token (add JTI to blocklist).

    Requires: Authorization: Bearer <access_token>
    """
    jti = get_jwt()["jti"]
    result = AuthService.logout(jti)
    return jsonify(result), 200
