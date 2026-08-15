"""Security hardening tests (millstone 8).

Covers the defenses added in the hardening pass:
* CSRF same-origin blocking;
* DNS-rebinding-safe HTTP connections (pinned resolve + connect);
* strict port parsing (no leading zeros / signs / hex);
* no raw OS error leakage in DNS/TCP messages;
* max_history floor is enforced by env config.
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from app.config import Config
from app.main import _same_origin
from app.network import dns as dns_svc
from app.network import http as http_svc
from app.network import tcp as tcp_svc
from app.services import dispatch
from app.validation import ValidationError, parse_port


# --- CSRF -------------------------------------------------------------------

def test_csrf_blocks_cross_origin_post(client):
    resp = client.post(
        "/tools/ping",
        data={"target": "example.com"},
        headers={"Origin": "http://evil.example"},
    )
    assert resp.status_code == 403


def test_csrf_blocks_cross_origin_with_host_spoof(client):
    resp = client.post(
        "/tools/tcp",
        data={"target": "example.com", "port": "443"},
        headers={"Origin": "http://127.0.0.1:5000", "Host": "evil.example"},
    )
    assert resp.status_code == 403


def test_csrf_allows_same_origin(client):
    resp = client.post(
        "/tools/ping",
        data={"target": "example.invalid"},
        headers={"Origin": "http://localhost"},
    )
    # The tool itself may 400/200; the point is origin passes (not 403).
    assert resp.status_code != 403


def test_csrf_allows_no_origin(client):
    """CLI / curl clients (no Origin) are not browsers; they pass."""
    resp = client.post("/tools/ping", data={"target": "example.invalid"})
    assert resp.status_code != 403


def test_same_origin_helper():
    assert _same_origin("http://127.0.0.1:5000", "http://127.0.0.1:5000") is True
    assert _same_origin("http://127.0.0.1:5000", "http://localhost:5000") is False
    assert _same_origin("https://x.com/a", "https://x.com/b") is True
    assert _same_origin("http://x.com", "https://x.com") is False
    assert _same_origin("", "http://x.com") is False


# --- DNS-rebinding-safe HTTP connect ----------------------------------------

def test_validated_http_connection_pins_resolved_ip(monkeypatch):
    """The validated connection must resolve+connect to an SSRF-allowed IP."""
    from app.network.http import _ValidatedHTTPConnection

    conn = _ValidatedHTTPConnection("example.test", 80)
    conn._allow_private = False
    conn._connect_timeout = 1.0
    conn._read_timeout = 1.0

    created = []

    class FakeSock:
        def settimeout(self, _t):
            pass

        def close(self):
            pass

    monkeypatch.setattr(
        http_svc.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )
    monkeypatch.setattr(
        http_svc.socket, "create_connection", lambda addr, timeout: FakeSock()
    )

    conn.connect()
    assert conn.sock is not None


def test_validated_http_connection_blocks_private(monkeypatch):
    """The validated connection must refuse an SSRF-blocked resolution."""
    from app.network.http import _ValidatedHTTPConnection, SsrfBlockedError

    conn = _ValidatedHTTPConnection("internal.test", 80)
    conn._allow_private = False

    monkeypatch.setattr(
        http_svc.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))
        ],
    )
    with pytest.raises(SsrfBlockedError):
        conn.connect()


def test_dns_rebinding_race_closed(monkeypatch):
    """Two sequential resolutions disagreeing must still connect to the safe one."""
    from app.network.http import _ValidatedHTTPConnection

    # The validated connection resolves the hostname exactly once (ours) and
    # connects to that pinned address; a second (hostile) resolution would
    # never be used because we build the socket ourselves.
    seen = []

    def fake_resolve(hostname, port, *_a, **_k):
        seen.append(("resolve", hostname, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    called_addr = []

    def fake_create_connection(addr, *_args, **_kw):
        called_addr.append(addr)

        class _FakeSock:
            def settimeout(self, _t):
                pass

            def close(self):
                pass

        return _FakeSock()

    monkeypatch.setattr(http_svc.socket, "getaddrinfo", fake_resolve)
    monkeypatch.setattr(http_svc.socket, "create_connection", fake_create_connection)

    conn = _ValidatedHTTPConnection("example.test", 80)
    conn._allow_private = False
    conn._connect_timeout = 1.0
    conn._read_timeout = 1.0

    conn.connect()

    assert len(seen) == 1  # resolution happens exactly once (pinned)
    assert called_addr[0][0] == "8.8.8.8"


# --- Strict port parsing ----------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    ["+443", " 443", "0x1bb", "04 43", "443 ", "abc", "", "65536", "0"],
)
def test_parse_port_rejects_ambiguous(bad):
    with pytest.raises(ValidationError):
        parse_port(bad)


@pytest.mark.parametrize("good", ["1", "80", "443", "65535"])
def test_parse_port_accepts_valid(good):
    assert parse_port(good) == int(good)


def test_parse_port_rejects_bool():
    with pytest.raises(ValidationError):
        parse_port(True)


# --- No OS error leakage ----------------------------------------------------

def test_dns_error_message_friendly(monkeypatch):
    def boom(_host, _port):
        raise socket.gaierror(socket.EAI_NONAME, "extremely_verbose_syslog_text")

    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", boom)
    result = dns_svc.lookup("nonexistent.invalid")
    assert "extremely_verbose_syslog_text" not in str(result["error"])
    assert "does not exist" in result["error"]


def test_tcp_error_message_friendly(monkeypatch):
    """Closed-port detail must not include raw errno or OS text."""
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", port))
        ],
    )

    class FakeSocket:
        def settimeout(self, _t):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_e):
            self.close()

        def close(self):
            pass

        def connect_ex(self, _addr):
            return 111  # ECONNREFUSED

    monkeypatch.setattr(tcp_svc.socket, "socket", lambda *a, **k: FakeSocket())
    result = tcp_svc.check("example.com", 80, timeout=1.0)
    assert "111" not in result["detail"]
    assert "refused" in result["detail"].lower()


# --- Config hardening -------------------------------------------------------

def test_max_history_env_capped(monkeypatch):
    import app.config as cfg_module

    monkeypatch.setenv("NETLITE_MAX_HISTORY", "99999999")
    cfg = cfg_module.Config.from_env()
    assert cfg.max_history <= cfg_module.MAX_HISTORY_LIMIT


def test_http_error_message_friendly():
    from app.network.http import _friendly_error

    msg = _friendly_error(OSError(111, "Connection refused"))
    assert "Connection refused" in msg