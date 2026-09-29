"""
app/utils/sanitizer.py — Log sanitization utilities.

Prevents credential leakage (C-4) and log injection attacks (CWE-117 / M-2)
by stripping sensitive keys from request bodies and removing CRLF sequences
from string values before they are persisted to MongoDB.
"""
from __future__ import annotations

import json
import re

# Fields whose values must NEVER appear in logs
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "confirm",
        "confirm_password",
        "new_password",
        "old_password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "credit_card",
        "cvv",
        "ssn",
    }
)

# CRLF injection pattern (CWE-117)
_CRLF_RE = re.compile(r"[\r\n\x00]")


def _strip_crlf(value: str) -> str:
    """Replace CRLF/null characters to prevent log injection."""
    return _CRLF_RE.sub(" ", value)


def sanitize_body(raw: str, content_type: str = "") -> str:
    """
    Redact sensitive fields from a request body string.

    - Attempts JSON parsing for application/json bodies.
    - Falls back to a regex scrub for form-encoded bodies.
    - Always strips CRLF characters.
    - Truncates at 4 KB to prevent log-bloat DoS.
    """
    MAX_BODY_LENGTH = 4096

    # Hard-truncate first to bound processing time
    raw = raw[:MAX_BODY_LENGTH]
    raw = _strip_crlf(raw)

    if "application/json" in content_type or raw.lstrip().startswith("{"):
        try:
            body: dict = json.loads(raw)
            return json.dumps(_redact_dict(body))
        except (json.JSONDecodeError, ValueError):
            pass

    # Regex fallback for form-encoded or unknown bodies
    for key in _SENSITIVE_KEYS:
        # Matches key=VALUE& or key=VALUE at end of string
        raw = re.sub(
            rf"(?i)({re.escape(key)}=)[^&\s]*",
            r"\1[REDACTED]",
            raw,
        )
    return raw


def _redact_dict(obj: object, depth: int = 0) -> object:
    """Recursively redact sensitive keys from a parsed JSON structure."""
    if depth > 10:          # Guard against deeply nested bombs
        return "[TRUNCATED]"

    if isinstance(obj, dict):
        return {
            k: "[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _redact_dict(v, depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_dict(item, depth + 1) for item in obj[:50]]  # cap list size
    if isinstance(obj, str):
        return _strip_crlf(obj)
    return obj


def sanitize_headers(headers: dict) -> dict:
    """
    Return a copy of the headers dict with the Authorization value masked.
    Preserves the header key so downstream tools still see it.
    """
    safe: dict = {}
    for k, v in headers.items():
        if k.lower() in ("authorization", "x-api-key", "cookie"):
            safe[k] = "[REDACTED]"
        else:
            safe[k] = _strip_crlf(str(v))
    return safe
