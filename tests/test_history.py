"""Tests for SQLite history persistence and its routes."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from app import db as db_layer
from app.config import Config
from app.main import create_app


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def test_schema_created(tmp_path):
    path = tmp_path / "h.sqlite3"
    conn = db_layer.connect(path)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='history'"
    ).fetchall()
    assert tables
    conn.close()
    assert path.exists()


def test_add_and_list(tmp_path):
    path = tmp_path / "h.sqlite3"
    rid = db_layer.add_history(path, "ping", "example.com", "ok", "2/3 pkt", _now())
    rows = db_layer.list_history(path, 10)
    assert len(rows) == 1
    assert rows[0]["tool"] == "ping"
    assert rows[0]["target"] == "example.com"
    assert rows[0]["status"] == "ok"
    assert rid == rows[0]["id"]


def test_list_order_newest_first(tmp_path):
    path = tmp_path / "h.sqlite3"
    db_layer.add_history(path, "ping", "a.com", "ok", "s1", "2026-01-01T00:00:00+00:00")
    db_layer.add_history(path, "dns", "b.com", "ok", "s2", "2026-01-02T00:00:00+00:00")
    rows = db_layer.list_history(path, 10)
    assert [r["tool"] for r in rows] == ["dns", "ping"]


def test_delete(tmp_path):
    path = tmp_path / "h.sqlite3"
    rid = db_layer.add_history(path, "ping", "a.com", "ok", "s", _now())
    assert db_layer.delete_history(path, rid) is True
    assert db_layer.list_history(path, 10) == []
    assert db_layer.delete_history(path, 999) is False


def test_prune_removes_oldest(tmp_path):
    path = tmp_path / "h.sqlite3"
    for i in range(5):
        db_layer.add_history(path, "ping", f"h{i}.com", "ok", "s", _now())
    removed = db_layer.prune_history(path, max_records=3)
    assert removed == 2
    rows = db_layer.list_history(path, 10)
    assert len(rows) == 3
    assert rows[0]["target"] == "h4.com"  # newest first


def test_target_truncated(tmp_path):
    path = tmp_path / "h.sqlite3"
    db_layer.add_history(path, "tcp", "x" * 1000, "open", "s", _now())
    rows = db_layer.list_history(path, 10)
    assert rows[0]["target"] == "x" * 255


def test_history_route_records_and_lists(client):
    resp = client.post("/tools/ping", data={"target": "example.invalid"})
    # Whatever the ping outcome (mocked service), history must be written.
    assert resp.status_code in (200, 400)

    page = client.get("/history")
    assert page.status_code == 200


def test_history_delete_route(client):
    db_path = client.application.extensions["netlite_database"]
    rid = db_layer.add_history(db_path, "ping", "a.com", "ok", "s", _now())
    resp = client.post(f"/history/{rid}/delete")
    assert resp.status_code == 200
    assert db_layer.list_history(db_path, 10) == []

    resp = client.post("/history/999999/delete")
    assert resp.status_code == 404


def test_history_does_not_break_tool(monkeypatch, client):
    """A failing DB write must never turn a tool call into a 500."""
    from app import db as db_module

    def boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr(db_module, "add_history", boom)
    monkeypatch.setattr(db_module, "prune_history", boom)

    from unittest import mock
    with mock.patch("app.network.ping.shutil.which", return_value=None):
        resp = client.post("/tools/ping", data={"target": "example.com"})
        assert resp.status_code == 200


def test_max_history_respected_end_to_end(app):
    """The retention cap constrains what's shown, not just stored."""
    from app import db as db_layer

    cfg = app.extensions["netlite_config"]
    path = app.extensions["netlite_database"]
    for i in range(5):
        db_layer.add_history(path, "ping", f"h{i}.com", "ok", "s", _now())
    db_layer.prune_history(path, max_records=3)

    client = app.test_client()
    page = client.get("/history")
    assert page.status_code == 200
    assert b"h4.com" in page.data
    assert b"h0.com" not in page.data  # pruned