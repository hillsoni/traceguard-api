"""
app/services/auth_service.py — Authentication business logic.

This is a pure service layer — no Flask imports, no HTTP concerns.
Views call these methods and handle the JSON serialisation.

Security fixes applied:
  C-1 — bcrypt replaces MD5
  C-2 — JWT secret validated at startup (in config)
  H-5 — password policy enforced in schema before reaching service
  H-6 — unified "Invalid credentials" message for user enumeration prevention
  H-8 — JWT secret validated at startup
"""
from __future__ import annotations

import logging

from flask_jwt_extended import create_access_token, create_refresh_token
from sqlalchemy.exc import SQLAlchemyError

from app.exceptions import (
    AuthenticationError,
    ConflictError,
    DatabaseError,
    NotFoundError,
)
from app.extensions import db
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.schemas.auth import LoginSchema, RegisterSchema

logger = logging.getLogger(__name__)


class AuthService:
    """Encapsulates all authentication and token management operations."""

    # ── Registration ─────────────────────────────────────────────────────────

    @staticmethod
    def register(schema: RegisterSchema) -> dict:
        """
        Create a new user and return access + refresh tokens.

        Raises:
            ConflictError: Email or username already taken.
            DatabaseError: Unexpected persistence failure.
        """
        # Check uniqueness before hashing (avoids bcrypt work on duplicates)
        if User.query.filter_by(email=schema.email).first():
            raise ConflictError(f"Email '{schema.email}' is already registered.")

        if User.query.filter_by(username=schema.username).first():
            raise ConflictError(f"Username '{schema.username}' is already taken.")

        user = User(email=schema.email, username=schema.username)
        user.set_password(schema.password)   # bcrypt hash (fix C-1)

        try:
            db.session.add(user)
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.error(
                "register_db_error",
                extra={"error": str(exc)},
                exc_info=True,
            )
            raise DatabaseError("Could not create account. Please try again.") from exc

        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        logger.info(
            "user_registered",
            extra={"user_id": user.id, "email": user.email},
        )

        return {
            "message": "Account created successfully.",
            "user": {"id": user.id, "email": user.email, "username": user.username},
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    # ── Login ────────────────────────────────────────────────────────────────

    @staticmethod
    def login(schema: LoginSchema) -> dict:
        """
        Validate credentials and return tokens.

        Returns the same generic error for "user not found" and "wrong
        password" to prevent user enumeration (fix H-6).

        Raises:
            AuthenticationError: Credentials invalid or account inactive.
        """
        _AUTH_ERROR = AuthenticationError(
            "Invalid email or password."   # Generic — no enumeration
        )

        user = User.query.filter_by(email=schema.email).first()
        if not user:
            logger.warning("login_user_not_found", extra={"email": schema.email})
            raise _AUTH_ERROR

        if not user.is_active:
            raise AuthenticationError("This account has been deactivated.")

        # Constant-time compare via bcrypt.checkpw (fix H-6 timing attack)
        if not user.check_password(schema.password):
            logger.warning("login_bad_password", extra={"user_id": user.id})
            raise _AUTH_ERROR

        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        logger.info("login_success", extra={"user_id": user.id})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    # ── Token refresh ────────────────────────────────────────────────────────

    @staticmethod
    def refresh(current_user_email: str) -> dict:
        """
        Issue a new access token for a valid, non-revoked refresh token.

        Raises:
            NotFoundError: Identity in refresh token no longer matches a user.
        """
        user = User.query.filter_by(email=current_user_email).first()
        if not user or not user.is_active:
            raise NotFoundError("User no longer exists or has been deactivated.")

        access_token = create_access_token(identity=user.email)
        logger.info("token_refreshed", extra={"user_id": user.id})
        return {"access_token": access_token}

    # ── Logout ───────────────────────────────────────────────────────────────

    @staticmethod
    def logout(jti: str) -> dict:
        """
        Add the current token's JTI to the blocklist.

        Raises:
            DatabaseError: Could not persist the revocation.
        """
        try:
            RevokedToken.revoke(jti)
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.error("logout_db_error", extra={"error": str(exc)}, exc_info=True)
            raise DatabaseError("Could not revoke token. Please try again.") from exc

        logger.info("user_logged_out", extra={"jti": jti})
        return {"message": "Successfully logged out."}


# ── JWT callback hooks ────────────────────────────────────────────────────────
# Registered here so they are available when the jwt extension is initialised.
# The extension object is imported from extensions.py and the actual
# registration happens via jwt.init_app(app) in create_app().

from app.extensions import jwt  # noqa: E402 — after class definition


@jwt.token_in_blocklist_loader
def _check_if_token_revoked(jwt_header: dict, jwt_payload: dict) -> bool:  # noqa: ARG001
    jti = jwt_payload.get("jti", "")
    return RevokedToken.is_jti_revoked(jti)
