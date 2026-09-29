"""
tests/test_health.py — Tests for health check endpoints.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestLiveness:

    def test_liveness_returns_200(self, client):
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_liveness_no_auth_required(self, client):
        """Health endpoints must be reachable without a token."""
        resp = client.get("/health/live")
        assert resp.status_code == 200


class TestReadiness:

    @patch("app.routes.health.db")
    @patch("app.routes.health.mongo")
    def test_readiness_all_healthy(self, mock_mongo, mock_db, client, app):
        mock_db.session.execute = MagicMock()
        mock_mongo.db.command = MagicMock()
        with app.app_context():
            resp = client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
