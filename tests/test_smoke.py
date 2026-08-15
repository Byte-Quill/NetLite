"""Smoke tests: app factory, health endpoint, and basic routing."""

from __future__ import annotations


def test_app_created(app):
    assert app is not None
    assert app.extensions["netlite_config"] is not None
    assert app.template_folder.endswith("templates")


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["app"] == "netlite"


def test_index_renders_dashboard(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Network Toolkit" in resp.data


def test_history_page_empty(client):
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"No history yet" in resp.data


def test_secure_headers_present(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_unknown_tool_returns_error_fragment(client):
    resp = client.post("/tools/unknown")
    assert resp.status_code == 404
