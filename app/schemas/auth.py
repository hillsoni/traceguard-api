"""
app/schemas/auth.py — Request/response validation schemas for auth endpoints.

Uses plain Python dataclasses + validation methods rather than pulling in
a heavy validation library. For projects that grow beyond a few endpoints,
migrate to marshmallow or pydantic-v2.

Key improvements over original code:
  - Missing fields → ValidationError (not KeyError → 500).
  - Proper email regex (RFC 5322-ish subset).
  - Password policy: 8–128 chars (drops the absurd 12-char cap, fixes H-5).
  - No field defaults that mask missing required data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.exceptions import ValidationError

# RFC 5322-ish subset — pragmatic, not 100% spec-compliant
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Password complexity: at least one letter AND one digit
_PASSWORD_LETTER_RE = re.compile(r"[a-zA-Z]")
_PASSWORD_DIGIT_RE = re.compile(r"[0-9]")

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{3,50}$")


@dataclass
class RegisterSchema:
    """Validated payload for POST /auth/register."""

    email: str
    username: str
    password: str
    confirm: str

    @classmethod
    def from_dict(cls, data: dict | None) -> "RegisterSchema":
        """
        Parse and validate a raw dict. Raises ValidationError with field-level
        details on any failure — never a KeyError.
        """
        if not isinstance(data, dict):
            raise ValidationError("Request body must be a JSON object.")

        errors: dict[str, str] = {}

        email = str(data.get("email", "")).strip().lower()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        confirm = str(data.get("confirm", ""))

        # ── Required field check ─────────────────────────────────────────────
        if not email:
            errors["email"] = "Email is required."
        elif not _EMAIL_RE.match(email):
            errors["email"] = "Invalid email address."

        if not username:
            errors["username"] = "Username is required."
        elif not _USERNAME_RE.match(username):
            errors["username"] = (
                "Username must be 3–50 characters and contain only "
                "letters, digits, underscores, hyphens, or dots."
            )

        if not password:
            errors["password"] = "Password is required."
        else:
            pw_errors = _validate_password(password)
            if pw_errors:
                errors["password"] = pw_errors

        if not confirm:
            errors["confirm"] = "Password confirmation is required."
        elif "password" not in errors and password != confirm:
            errors["confirm"] = "Passwords do not match."

        if errors:
            raise ValidationError("Validation failed.", details=errors)

        return cls(
            email=email,
            username=username,
            password=password,
            confirm=confirm,
        )


@dataclass
class LoginSchema:
    """Validated payload for POST /auth/login."""

    email: str
    password: str

    @classmethod
    def from_dict(cls, data: dict | None) -> "LoginSchema":
        if not isinstance(data, dict):
            raise ValidationError("Request body must be a JSON object.")

        errors: dict[str, str] = {}

        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."

        if errors:
            raise ValidationError("Validation failed.", details=errors)

        return cls(email=email, password=password)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _validate_password(pw: str) -> str | None:
    """
    Return an error message string if the password is invalid, else None.
    Policy: 8–128 chars, at least one letter, at least one digit.
    """
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if len(pw) > 128:
        return "Password must not exceed 128 characters."
    if not _PASSWORD_LETTER_RE.search(pw):
        return "Password must contain at least one letter."
    if not _PASSWORD_DIGIT_RE.search(pw):
        return "Password must contain at least one digit."
    return None
