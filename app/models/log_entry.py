"""
app/models/log_entry.py — MongoDB log entry schema helper.

Not a SQLAlchemy model — MongoDB is schemaless. This module provides a
dataclass that represents a canonical log entry, a factory to build one
from a Flask request/response, and a safe to_dict() that never raises
KeyError on missing fields (fixes M-4).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class LogEntry:
    """
    Typed representation of a persisted request/response log document.

    All fields are optional so that partial documents (e.g., before the
    response is available) can be created without error.
    """

    request_id: str = ""
    timestamp: str = ""
    user: Optional[str] = None
    remote_addr: str = ""
    method: str = ""
    scheme: str = ""
    path: str = ""
    url: str = ""
    content_type: str = ""
    body: str = ""                  # sanitized — never raw password
    status: Optional[str] = None
    response_body: str = ""         # sanitized
    duration_ms: Optional[float] = None
    exception: Optional[str] = None  # str(exc), not the object itself (fix L-3)

    def to_dict(self) -> dict:
        """
        Return a dict suitable for MongoDB insertion.
        Uses dataclasses.asdict() — no KeyError risk (fixes M-4).
        """
        return {k: v for k, v in asdict(self).items() if v is not None}
