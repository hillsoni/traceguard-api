"""
tests/test_sanitizer.py — Unit tests for the log sanitization utilities.

Covers both the happy path and adversarial inputs (CWE-117, credential leakage).
"""
from __future__ import annotations

from app.utils.sanitizer import _redact_dict, sanitize_body, sanitize_headers


class TestSanitizeBody:

    def test_redacts_password_field(self):
        raw = '{"email": "a@b.com", "password": "s3cret"}'
        result = sanitize_body(raw, content_type="application/json")
        assert "s3cret" not in result
        assert "[REDACTED]" in result

    def test_redacts_nested_sensitive_field(self):
        raw = '{"user": {"password": "hunter2", "name": "Alice"}}'
        result = sanitize_body(raw, content_type="application/json")
        assert "hunter2" not in result

    def test_preserves_non_sensitive_fields(self):
        raw = '{"email": "alice@example.com", "username": "alice"}'
        result = sanitize_body(raw, content_type="application/json")
        assert "alice@example.com" in result
        assert "alice" in result

    def test_strips_crlf_injection(self):
        """CWE-117: CRLF must be stripped from logged values."""
        raw = '{"note": "line1\\r\\nFAKE LOG ENTRY"}'
        result = sanitize_body(raw, content_type="application/json")
        assert "\r\n" not in result
        assert "\n" not in result

    def test_truncates_large_body(self):
        raw = "x" * 10_000
        result = sanitize_body(raw)
        assert len(result) <= 4096

    def test_handles_invalid_json_gracefully(self):
        raw = "not { valid json }"
        result = sanitize_body(raw, content_type="application/json")
        # Should not raise; returns the raw string (CRLF-stripped)
        assert isinstance(result, str)

    def test_handles_empty_string(self):
        assert sanitize_body("") == ""


class TestSanitizeHeaders:

    def test_redacts_authorization(self):
        headers = {"Authorization": "Bearer supersecrettoken", "Content-Type": "application/json"}
        result = sanitize_headers(headers)
        assert result["Authorization"] == "[REDACTED]"
        assert result["Content-Type"] == "application/json"

    def test_redacts_cookie(self):
        headers = {"Cookie": "session=abc123"}
        result = sanitize_headers(headers)
        assert result["Cookie"] == "[REDACTED]"

    def test_strips_crlf_from_header_values(self):
        headers = {"X-Custom": "value\r\nX-Injected: evil"}
        result = sanitize_headers(headers)
        assert "\r\n" not in result["X-Custom"]


class TestRedactDict:

    def test_handles_list_of_dicts(self):
        obj = [{"password": "s3cret"}, {"username": "alice"}]
        result = _redact_dict(obj)
        assert result[0]["password"] == "[REDACTED]"
        assert result[1]["username"] == "alice"

    def test_handles_deeply_nested(self):
        obj = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "deep"}}}}}}}}}}}}
        result = _redact_dict(obj)
        # Should not raise; deeply nested values are truncated
        assert isinstance(result, dict)
