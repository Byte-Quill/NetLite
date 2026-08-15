"""Additional quality tests (Milestone 9).

Covers the remaining branches surfaced by coverage: route error/timeout
paths, the bounded runner, app error handlers, HTTP inspector timeout and
redirect branches, and config edge cases.
"""

from __future__ import annotations

import socket
import urllib.error
from unittest import mock

import pytest

from app.config import Config
from app.network import http as http_svc
from app.services import runner
from app.services.dispatch import run_tool
from app.validation import ValidationError, normalize_hostname, parse_url

# --- Runner ----------------------------------------------------------------

def test_runner_propagates_timeout():
    def slow():
        import time

        time.sleep(5)

    with pytest.raises(runner.ToolTimeout):
        runner.run_with_timeout(slow, 0.05)


def test_runner_propagates_exception():
    def boom():
        raise ValueError("bad")

    with pytest.raises(ValueError, match="bad"):
        runner.run_with_timeout(boom, 5.0)


def test_runner_returns_value():
    def ok():
        return 42

    assert runner.run_with_timeout(ok, 5.0) == 42


# --- Route timeout / error paths --------------------------------------------

def test_route_returns_408_on_tool_timeout(client):
    """The route maps a ToolTimeout to a 408 response with a friendly message."""
    with mock.patch(
        "app.routes.tools.run_tool",
        side_effect=runner.ToolTimeout("Operation timed out after 1.0s."),
    ):
        resp = client.post("/tools/ping", data={"target": "example.com"})
        assert resp.status_code == 408
        assert b"timed out" in resp.data.lower()


def test_route_returns_400_on_validation_error(client):
    with mock.patch(
        "app.routes.tools.run_tool", side_effect=ValidationError("Invalid input.")
    ):
        resp = client.post("/tools/ping", data={"target": "example.com"})
        assert resp.status_code == 400
        assert b"Invalid input" in resp.data


def test_route_returns_500_hides_internals(client):
    with mock.patch("app.routes.tools.run_tool", side_effect=RuntimeError("secret internals")):
        resp = client.post("/tools/ping", data={"target": "example.com"})
        assert resp.status_code == 500
        assert b"secret internals" not in resp.data
        assert b"failed unexpectedly" in resp.data


# --- Validation edge cases --------------------------------------------------

def test_normalize_hostname_rejects_control_chars():
    for bad in ["exa\nmple.com", "exa\tmple.com", "example\x00.com"]:
        with pytest.raises(ValidationError):
            normalize_hostname(bad)


def test_normalize_hostname_idna():
    assert normalize_hostname("bücher.de") == "xn--bcher-kva.de"
    assert normalize_hostname("BÜCHER.DE") == "xn--bcher-kva.de"


def test_normalize_hostname_strips_trailing_dot():
    assert normalize_hostname("example.com.") == "example.com"


def test_normalize_hostname_rejects_oversized():
    with pytest.raises(ValidationError):
        normalize_hostname("a" * 254)


def test_normalize_hostname_rejects_labels_gt_63():
    with pytest.raises(ValidationError):
        normalize_hostname("a" * 64 + ".com")


def test_parse_url_rejects_userinfo():
    with pytest.raises(ValidationError):
        parse_url("http://user:pass@example.com/")


def test_parse_url_rejects_fragment_only():
    with pytest.raises(ValidationError):
        parse_url("http://example.com/#frag")


def test_parse_url_accepts_ipv6_host():
    parsed = parse_url("http://[::1]:8080/path")
    assert parsed.hostname == "::1"
    assert parsed.port == 8080


def test_parse_url_rejects_bad_scheme():
    with pytest.raises(ValidationError):
        parse_url("file:///etc/passwd")
    with pytest.raises(ValidationError):
        parse_url("ftp://example.com/")


def test_parse_url_rejects_empty():
    for bad in ["", "   ", "example.com"]:
        with pytest.raises(ValidationError):
            parse_url(bad)


# --- HTTP inspector branches ------------------------------------------------

def test_http_redirect_cap_blocks_loop(monkeypatch):
    """More than MAX_REDIRECTS must surface as an error, not hang."""
    from app.network.http import (
        MAX_REDIRECTS,
        SsrfBlockedError,
        _SsrfRedirectHandler,
    )

    # Public resolution so the SSRF guard passes; only the redirect cap counts.
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ],
    )
    handler = _SsrfRedirectHandler(allow_private=False)
    req = mock.Mock(full_url="http://example.com/", method="GET")

    # Simulate the cap: raise count beyond MAX_REDIRECTS and assert the guard.
    handler.count = MAX_REDIRECTS + 1
    with pytest.raises(SsrfBlockedError):
        handler.redirect_request(req, None, 302, "Found", {}, "http://example.com/hop")


def test_http_connection_refused_maps_friendly():
    from app.network.http import _friendly_error

    # OSError passed directly hits the generic fallback (still friendly).
    msg = _friendly_error(OSError(111, "Connection refused"))
    assert "Request failed" in msg or "Connection" in msg


def test_inspect_timeout_via_urn(monkeypatch):
    """URLError(TimeoutError) maps to the 'timed out' message."""
    opener = mock.MagicMock()
    opener.open.side_effect = urllib.error.URLError(TimeoutError("t"))
    build = mock.MagicMock(return_value=opener)
    monkeypatch.setattr(http_svc.urllib.request, "build_opener", build)
    cfg = Config(connect_timeout=1.0, read_timeout=1.0)
    r = http_svc.inspect("http://example.com/", cfg)
    assert "timed out" in r["error"].lower()


# --- Config edge cases ------------------------------------------------------

def test_config_env_ordering(monkeypatch):
    import app.config as cfg_module

    monkeypatch.setenv("NETLITE_PORT", "8080")
    monkeypatch.setenv("NETLITE_MAX_CONTENT_LENGTH", "2048")
    cfg = cfg_module.Config.from_env()
    assert cfg.port == 8080
    assert cfg.max_content_length == 2048


def test_config_env_invalid_raises(monkeypatch):
    import app.config as cfg_module

    monkeypatch.setenv("NETLITE_PORT", "not-a-port")
    with pytest.raises(ValueError):
        cfg_module.Config.from_env()


def test_config_allow_private_env(monkeypatch):
    import app.config as cfg_module

    monkeypatch.setenv("NETLITE_ALLOW_PRIVATE", "1")
    assert cfg_module.Config.from_env().allow_private is True
    monkeypatch.setenv("NETLITE_ALLOW_PRIVATE", "")
    assert cfg_module.Config.from_env().allow_private is False


# --- Dispatch unknown tool --------------------------------------------------

def test_dispatch_unknown_tool():
    from app.config import Config

    with pytest.raises(ValidationError, match="Unknown tool"):
        run_tool("nope", target="x", config=Config())
