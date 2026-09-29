"""
app/models/revoked_token.py — JWT blocklist model.

Stores JTIs (JWT IDs) of revoked tokens. Indexed on jti for O(1) lookups
during the token_in_blocklist_loader callback on every authenticated request.
"""
from __future__ import annotations

from app.extensions import db


class RevokedToken(db.Model):
    """
    JWT blocklist entry. A token whose jti appears here is considered
    revoked regardless of its expiry timestamp.
    """

    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    # SHA-256 JTI is 36 chars (UUID format); String(36) is sufficient.
    # Index=True provides O(log n) lookup — critical for high-traffic APIs.
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    revoked_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=db.func.now(),
    )

    @classmethod
    def is_jti_revoked(cls, jti: str) -> bool:
        """Return True if this JTI has been revoked."""
        return db.session.query(
            cls.query.filter_by(jti=jti).exists()
        ).scalar()

    @classmethod
    def revoke(cls, jti: str) -> "RevokedToken":
        """
        Add a jti to the blocklist and commit.
        Raises DatabaseError (via the service layer) on commit failure.
        """
        entry = cls(jti=jti)
        db.session.add(entry)
        db.session.commit()
        return entry

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RevokedToken jti={self.jti!r}>"