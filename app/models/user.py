"""
app/models/user.py — SQLAlchemy User model.

Passwords are stored as bcrypt hashes (60-char fixed-length string).
The model exposes check_password() for timing-safe comparison, keeping
all credential logic inside the model layer.
"""
from __future__ import annotations

import bcrypt

from app.extensions import db


class User(db.Model):
    """
    Represents an authenticated API user stored in PostgreSQL.

    Password hashing strategy: bcrypt with cost factor 12 (≈ 250 ms on
    a modern server). Never stored in plaintext. MD5 removed (fix C-1).
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    # bcrypt always produces 60-byte strings
    password_hash = db.Column(db.String(60), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=db.func.now(),
    )

    # ── Password helpers ─────────────────────────────────────────────────────

    def set_password(self, plaintext: str) -> None:
        """Hash plaintext with bcrypt (cost=12) and store the result."""
        self.password_hash = bcrypt.hashpw(
            plaintext.encode("utf-8"),
            bcrypt.gensalt(rounds=12),
        ).decode("utf-8")

    def check_password(self, plaintext: str) -> bool:
        """
        Constant-time comparison via bcrypt.checkpw.
        Returns False (not raises) on mismatch, preventing timing attacks.
        """
        try:
            return bcrypt.checkpw(
                plaintext.encode("utf-8"),
                self.password_hash.encode("utf-8"),
            )
        except Exception:
            return False

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email!r}>"
