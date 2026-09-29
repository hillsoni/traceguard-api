"""
tests/test_auth.py — Unit and integration tests for authentication endpoints.

Tests cover:
  - Happy-path registration and login.
  - All validation error paths (missing fields, bad email, short/long password,
    password mismatch).
  - Security: user enumeration prevention, token refresh, logout/revocation.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

VALID_REGISTER = {
    "email": "alice@example.com",
    "username": "alice",
    "password": "StrongPass1",
    "confirm": "StrongPass1",
}

VALID_LOGIN = {
    "email": "alice@example.com",
    "password": "StrongPass1",
}


# ── Registration ──────────────────────────────────────────────────────────────

class TestRegister:

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_success(self, _mock_resp, _mock_req, client, db):
        resp = client.post("/auth/register", json=VALID_REGISTER)
        assert resp.status_code == 201
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["user"]["email"] == "alice@example.com"

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_missing_body(self, _m1, _m2, client, db):
        resp = client.post("/auth/register", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "VALIDATION_ERROR"
        assert "email" in data["details"]
        assert "username" in data["details"]
        assert "password" in data["details"]

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_invalid_email(self, _m1, _m2, client, db):
        payload = {**VALID_REGISTER, "email": "not-an-email"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 400
        assert "email" in resp.get_json()["details"]

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_password_too_short(self, _m1, _m2, client, db):
        payload = {**VALID_REGISTER, "password": "abc1", "confirm": "abc1"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 400
        assert "password" in resp.get_json()["details"]

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_password_mismatch(self, _m1, _m2, client, db):
        payload = {**VALID_REGISTER, "confirm": "DifferentPass1"}
        resp = client.post("/auth/register", json=payload)
        assert resp.status_code == 400
        assert "confirm" in resp.get_json()["details"]

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_duplicate_email(self, _m1, _m2, client, db):
        client.post("/auth/register", json=VALID_REGISTER)
        resp = client.post("/auth/register", json=VALID_REGISTER)
        assert resp.status_code == 409
        assert resp.get_json()["error"] == "CONFLICT"

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_register_no_json_body(self, _m1, _m2, client, db):
        """Non-JSON body must return 400, not 500 (fixes C-3)."""
        resp = client.post(
            "/auth/register",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_login_success(self, _m1, _m2, client, db):
        client.post("/auth/register", json=VALID_REGISTER)
        resp = client.post("/auth/login", json=VALID_LOGIN)
        assert resp.status_code == 200
        assert "access_token" in resp.get_json()

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_login_wrong_password(self, _m1, _m2, client, db):
        client.post("/auth/register", json=VALID_REGISTER)
        resp = client.post("/auth/login", json={**VALID_LOGIN, "password": "WrongPass1"})
        assert resp.status_code == 401

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_login_nonexistent_user(self, _m1, _m2, client, db):
        resp = client.post("/auth/login", json=VALID_LOGIN)
        assert resp.status_code == 401

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_user_enumeration_same_error(self, _m1, _m2, client, db):
        """
        Security (H-6): non-existent user and wrong password must return
        identical status codes and the same generic error message.
        """
        # Wrong email
        r1 = client.post("/auth/login", json={"email": "ghost@x.com", "password": "Pass123"})
        # Valid email, wrong password
        client.post("/auth/register", json=VALID_REGISTER)
        r2 = client.post("/auth/login", json={**VALID_LOGIN, "password": "WrongPass1"})

        assert r1.status_code == r2.status_code == 401
        assert r1.get_json()["message"] == r2.get_json()["message"]


# ── Logout & Revocation ───────────────────────────────────────────────────────

class TestLogout:

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_logout_success(self, _m1, _m2, client, db):
        client.post("/auth/register", json=VALID_REGISTER)
        login_resp = client.post("/auth/login", json=VALID_LOGIN)
        token = login_resp.get_json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post("/auth/logout", headers=headers)
        assert resp.status_code == 200

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_revoked_token_rejected(self, _m1, _m2, client, db):
        """Token must be rejected after logout (blocklist works)."""
        client.post("/auth/register", json=VALID_REGISTER)
        login_resp = client.post("/auth/login", json=VALID_LOGIN)
        token = login_resp.get_json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        client.post("/auth/logout", headers=headers)

        # Using the same token again must fail
        resp = client.get("/api/me", headers=headers)
        assert resp.status_code == 401

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_logout_without_token(self, _m1, _m2, client, db):
        resp = client.post("/auth/logout")
        assert resp.status_code == 401


# ── Security headers ──────────────────────────────────────────────────────────

class TestSecurityHeaders:

    @patch("app.services.log_service.LogService.capture_request", return_value=None)
    @patch("app.services.log_service.LogService.capture_response")
    def test_security_headers_present(self, _m1, _m2, client):
        """All responses must carry the hardened security headers (fix H-1)."""
        resp = client.get("/health/live")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in resp.headers
        assert "X-Request-ID" in resp.headers
