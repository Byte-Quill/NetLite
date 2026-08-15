"""Shared pytest fixtures."""

from __future__ import annotations

import socket
import threading

import pytest

from app.config import Config
from app.main import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def tmp_instance(tmp_path_factory):
    return tmp_path_factory.mktemp("instance")


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


@pytest.fixture()
def netlite_config(app):
    return app.extensions["netlite_config"]


def run_server(app, port):
    """Run the Flask app in a background thread for integration tests."""

    def serve():
        app.run(host="127.0.0.1", port=port, use_reloader=False, threaded=True)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread
