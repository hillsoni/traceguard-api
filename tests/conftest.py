"""
tests/conftest.py — Pytest fixtures shared across all test modules.

Uses TestingConfig (in-memory SQLite, disabled rate limits) so tests
run without any external services. MongoDB interactions are mocked via
unittest.mock.patch.
"""
from __future__ import annotations

import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db as _db


@pytest.fixture(scope="session")
def app():
    """Create a single Flask app instance for the test session."""
    application = create_app(TestingConfig)
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="session")
def client(app):
    """Return a test client bound to the session-scoped app."""
    return app.test_client()


@pytest.fixture(scope="function")
def db(app):
    """
    Create all tables before each test and drop them after.
    Ensures test isolation even when tests create/modify DB rows.
    """
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def auth_headers(client, db):
    """
    Register + login a test user and return Authorization headers.
    Use this fixture in tests that require a valid JWT.
    """
    # Register
    client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass1",
            "confirm": "SecurePass1",
        },
    )
    # Login
    resp = client.post(
        "/auth/login",
        json={"email": "test@example.com", "password": "SecurePass1"},
    )
    data = resp.get_json()
    token = data.get("access_token", "")
    return {"Authorization": f"Bearer {token}"}
