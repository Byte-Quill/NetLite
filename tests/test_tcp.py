"""Tests for the TCP port checker.

All network behavior is mocked so tests never actually open sockets: we stub
``socket.socket`` and ``socket.getaddrinfo`` to simulate open/closed/timeout
outcomes.  The distinct UI states (open/closed/timeout/invalid) are each
covered, plus port validation and route-level integration.
"""

from __future__ import annotations

import socket
from unittest import mock

from app.network import tcp as tcp_svc


class _FakeSocket:
    """Minimal socket stub whose connect_ex returns a scripted result."""

    def __init__(self, result: int = 0):
        self._result = result
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def close(self):
        self.closed = True

    def connect_ex(self, _sockaddr):
        return self._result

    def connect(self, _sockaddr):
        if self._result != 0:
            raise OSError(f"connect failed with errno {self._result}")


def _fake_addrinfo(host, port, family=socket.AF_INET):
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.2.3.4", port))]


def _patch_network(monkeypatch, result: int = 0, family=socket.AF_INET):
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: (
            [_fake_addrinfo(host, port)[0]] if family else _fake_addrinfo(host, port)
        ),
    )
    monkeypatch.setattr(tcp_svc.socket, "socket", lambda *args, **kw: _FakeSocket(result))


def test_open_port(monkeypatch):
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: _fake_addrinfo(host, port),
    )
    monkeypatch.setattr(tcp_svc.socket, "socket", lambda *a, **k: _FakeSocket(result=0))
    result = tcp_svc.check("example.com", 443, timeout=1.0)
    assert result["status"] == "open"
    assert result["resolved"] == ["1.2.3.4"]


def test_closed_port(monkeypatch):
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: _fake_addrinfo(host, port),
    )
    monkeypatch.setattr(tcp_svc.socket, "socket", lambda *a, **k: _FakeSocket(result=111))
    result = tcp_svc.check("example.com", 80, timeout=1.0)
    assert result["status"] == "closed"


def test_timeout(monkeypatch):
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: _fake_addrinfo(host, port),
    )

    class TimeoutSocket(_FakeSocket):
        def connect_ex(self, _sockaddr):
            raise TimeoutError("timed out")

    monkeypatch.setattr(tcp_svc.socket, "socket", lambda *a, **k: TimeoutSocket())
    result = tcp_svc.check("example.com", 80, timeout=1.0)
    assert result["status"] == "timeout"


def test_invalid_port_never_resolves(monkeypatch):
    # Even if DNS were to succeed, the port validator must short-circuit.
    monkeypatch.setattr(
        tcp_svc.socket,
        "getaddrinfo",
        lambda host, port: _fake_addrinfo(host, port),
    )
    result = tcp_svc.check("example.com", 70000, timeout=1.0)
    assert result["status"] == "invalid"
    assert result["resolved"] is None


def test_port_zero_rejected():
    result = tcp_svc.check("example.com", 0, timeout=1.0)
    assert result["status"] == "invalid"
    assert result["resolved"] is None


def test_negative_port_rejected():
    result = tcp_svc.check("example.com", -1, timeout=1.0)
    assert result["status"] == "invalid"


def test_dns_failure_reported(monkeypatch):
    def boom(_host, _port):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(tcp_svc.socket, "getaddrinfo", boom)
    result = tcp_svc.check("no-such-host.invalid", 80, timeout=1.0)
    assert result["status"] == "invalid"
    assert result["resolved"] is None


def test_tcp_route_valid(client):
    with mock.patch("app.network.tcp.socket.getaddrinfo") as ga:
        ga.return_value = _fake_addrinfo("example.com", 443)
        with mock.patch("app.network.tcp.socket.socket") as sock:
            sock.return_value = _FakeSocket(result=0)
            resp = client.post("/tools/tcp", data={"target": "example.com", "port": "443"})
            assert resp.status_code == 200
            assert b'data-tool-result="tcp"' in resp.data


def test_tcp_route_invalid_port(client):
    resp = client.post("/tools/tcp", data={"target": "example.com", "port": "70000"})
    assert resp.status_code == 400
    assert b"result-error" in resp.data


def test_tcp_route_missing_port(client):
    resp = client.post("/tools/tcp", data={"target": "example.com"})
    assert resp.status_code == 400
