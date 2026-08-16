"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from app.config import Config
from app.main import create_app


@pytest.fixture()
def app(tmp_path):
    """A configured Flask app with an isolated, ephemeral database."""
    db_path = tmp_path / "test.sqlite3"
    cfg = Config(
        secret_key="test-secret",
        database=db_path,
        max_history=50,
        connect_timeout=1.0,
        read_timeout=1.0,
        ping_timeout=1.0,
        allow_private=False,
    )
    app = create_app(cfg)
    app.config.update(TESTING=True)
    yield app


@pytest.fixture()
def client(app):
    """Test client bound to the ephemeral app."""
    return app.test_client()
