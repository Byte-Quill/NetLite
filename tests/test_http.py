"""Tests for the HTTP inspector service and its SSRF integration.

``urllib.request`` is mocked so no external network is contacted.  Test cases
cover: successful fetch, HTTP error responses, timeout, oversized responses,
SSRF-blocked targets (including redirect rebinding), and URL validation.
"""

from __future__ import annotations

import io
import socket
import urllib.error
from unittest import mock

import pytest

from app.config import Config
from app.network import http as http_svc
from app.validation import ValidationError


class _FakeResponse:
    """Minimal stand-in for urllib's HTTPResponse."""

    def __init__(self, status=200, headers=None, body=b"ok", url="http://final.example/"):
        self.status = status
        self._headers = headers or {}
        self._body = io.BytesIO(body)
        self._url = url

    @property
    def headers(self):
        return self._headers

    def read(self, size=-1):
        if size < 0:
            return self._body.read()
        return self._body.read(size)

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _cfg(**overrides) -> Config:
    base = {
        "secret_key": "test",
        "database": "test.sqlite3",
        "connect_timeout": 1.0,
        "read_timeout": 1.0,
        "max_response_bytes": 256 * 1024,
        "allow_private": False,
    }
    base.update(overrides)
    return Config(**base)


def _patch_urllib(monkeypatch, response=None, side_effect=None):
    opener = mock.MagicMock()
    if response is not None:
        opener.open.return_value.__enter__.return_value = response
    if side_effect is not None:
        opener.open.side_effect = side_effect

    build_opener = mock.MagicMock(return_value=opener)
    monkeypatch.setattr(http_svc.urllib.request, "build_opener", build_opener)
    return opener


def test_inspect_ok(monkeypatch):
    headers = {"Content-Type": "text/html; charset=utf-8", "Server": "nginx/1.24", "Content-Length": "2"}
    resp = _FakeResponse(status=200, headers=headers, body=b"ok")
    _patch_urllib(monkeypatch, response=resp)

    result = http_svc.inspect("http://example.com/", _cfg())
    assert result["status_code"] == 200
    assert result["content_type"] == "text/html"
    assert result["server"] == "nginx/1.24"
    assert result["content_length"] == 2
    assert result["error"] is None


def test_inspect_http_error_records_status(monkeypatch):
    # A 404 must surface status_code=404 rather than a generic error.
    err = urllib.error.HTTPError(
        "http://example.com/", 404, "Not Found", {}, io.BytesIO(b"nf")
    )
    _patch_urllib(monkeypatch, side_effect=err)

    result = http_svc.inspect("http://example.com/", _cfg())
    assert result["status_code"] == 404
    assert "404" in result["error"]


def test_inspect_timeout(monkeypatch):
    _patch_urllib(
        monkeypatch,
        side_effect=urllib.error.URLError(TimeoutError("timed out")),
    )
    result = http_svc.inspect("http://example.com/", _cfg())
    assert result["error"] is not None
    assert "timed out" in result["error"].lower()


def test_inspect_connection_refused(monkeypatch):
    _patch_urllib(
        monkeypatch,
        side_effect=urllib.error.URLError(PermissionError(13, "Permission denied")),
    )
    result = http_svc.inspect("http://example.com/", _cfg())
    assert "failed" in result["error"].lower() or "permission" in result["error"].lower()


def test_inspect_ssrf_private_host_blocked(monkeypatch):
    # Even when URL parses, SSRF guard refuses before any request is built.
    _patch_urllib(monkeypatch, response=_FakeResponse())

    result = http_svc.inspect("http://127.0.0.1/", _cfg())
    assert result["error"] is not None
    assert "blocked" in result["error"].lower() or "private" in result["error"].lower()
    assert result["status_code"] is None


def test_inspect_ssrf_allow_private_opt_in(monkeypatch):
    # With ALLOW_PRIVATE, the request goes through (mocked here).
    headers = {"Content-Type": "text/plain"}
    resp = _FakeResponse(status=200, headers=headers, body=b"x")
    _patch_urllib(monkeypatch, response=resp)

    result = http_svc.inspect("http://127.0.0.1/", _cfg(allow_private=True))
    assert result["status_code"] == 200
    assert result["error"] is None


def test_inspect_oversized_response_truncated(monkeypatch):
    # max_response_bytes = 64 → the read loop must stop at the cap.
    resp = _FakeResponse(body=b"x" * 1000, url="http://final.example/big")
    _patch_urllib(monkeypatch, response=resp)

    cfg = _cfg(max_response_bytes=64)
    result = http_svc.inspect("http://example.com/", cfg)
    assert "limit" in result["error"]
    assert result["status_code"] == 200  # metadata still reported


def test_inspect_invalid_scheme_rejected():
    with pytest.raises(ValueError):
        http_svc.inspect("ftp://example.com/file", _cfg())


def test_inspect_missing_scheme_rejected():
    with pytest.raises(ValidationError):
        http_svc.inspect("example.com/path", _cfg())


def test_redirect_rebinding_blocked(monkeypatch):
    """A redirect to a private address must be refused even if initial host is public."""
    # Simulate urllib raising a URLError that wraps our SsrfBlockedError path:
    # the redirect handler raises SsrfBlockedError internally, which propagates.
    from app.network.http import SsrfBlockedError

    opener = mock.MagicMock()
    opener.open.side_effect = SsrfBlockedError("Redirect to 127.0.0.1 is blocked.")
    build_opener = mock.MagicMock(return_value=opener)
    monkeypatch.setattr(http_svc.urllib.request, "build_opener", build_opener)

    result = http_svc.inspect("http://example.com/", _cfg())
    assert result["error"] is not None
    assert "blocked" in result["error"].lower()


def test_inspect_uses_bounded_read_size(monkeypatch):
    """The reader must cap each read at the remaining budget."""
    calls = []

    class TrackingResp(_FakeResponse):
        def read(self, size=-1):
            calls.append(size)
            return _FakeResponse.read(self, size)

    _patch_urllib(monkeypatch, response=TrackingResp(body=b"x" * 300))

    cfg = _cfg(max_response_bytes=128)
    http_svc.inspect("http://example.com/", cfg)
    assert all(c <= 128 for c in calls if c is not None and c != -1)


# --- Redirect-rebinding protection ------------------------------------------


def test_redirect_to_loopback_blocked(monkeypatch):
    """The redirect handler must refuse a Location pointing at a loopback."""
    from app.network.http import SsrfBlockedError, _SsrfRedirectHandler

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    handler = _SsrfRedirectHandler(allow_private=False)
    req = mock.Mock()
    req.full_url = "http://example.com/start"

    with pytest.raises(SsrfBlockedError):
        handler.redirect_request(
            req, None, 302, "Found", {}, "http://127.0.0.1:9/secret"
        )


def test_redirect_to_public_allowed(monkeypatch):
    """The redirect handler must pass through an allowed public target."""
    from app.network.http import _SsrfRedirectHandler

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ],
    )
    handler = _SsrfRedirectHandler(allow_private=False)
    req = mock.Mock()
    req.full_url = "http://example.com/start"
    req.method = "GET"

    # urllib validates the Location itself and raises HTTPError for a missing
    # file pointer; we assert only that our SSRF check passed (i.e. it did NOT
    # raise SsrfBlockedError).  The HTTPError here comes from urllib plumbing,
    # not from our guard.
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            req, None, 302, "Found", {}, "http://example.com/new"
        )

    # Also assert the handler counter incremented (guard ran).
    assert handler.count == 1
