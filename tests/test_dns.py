"""Tests for the DNS lookup service.

The OS resolver is never hit by the unit tests: ``socket.getaddrinfo`` is
mocked to return representative address sets, and the failure paths exercise
real error objects.
"""

from __future__ import annotations

import socket
from unittest import mock

from app.network import dns as dns_svc


def _fake_addrinfo(entries):
    """Build a list of (family, type, proto, canon, sockaddr) tuples.

    ``entries`` is a list of (family, address) pairs; sockaddr is a 2-tuple
    for IPv4 and a 4-tuple for IPv6.
    """
    out = []
    for family, addr in entries:
        if family == socket.AF_INET:
            sockaddr = (addr, 0)
        else:
            sockaddr = (addr, 0, 0, 0)
        out.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    return out


def test_lookup_returns_ipv4_and_ipv6(monkeypatch):
    infos = _fake_addrinfo(
        [
            (socket.AF_INET, "93.184.216.34"),
            (socket.AF_INET, "93.184.216.35"),
            (socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"),
        ]
    )
    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", lambda host, port: infos)
    # Canonical reverse lookup would block on the OS resolver; stub it to fail
    # fast so the unit is deterministic and offline.
    monkeypatch.setattr(
        dns_svc.socket,
        "getnameinfo",
        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, "")),
    )
    result = dns_svc.lookup("example.com")
    assert result["ipv4"] == ["93.184.216.34", "93.184.216.35"]
    assert result["ipv6"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert result["error"] is None


def test_lookup_no_addresses_is_error(monkeypatch):
    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", lambda host, port: [])
    result = dns_svc.lookup("example.com")
    assert result["error"] is not None
    assert result["ipv4"] == []
    assert result["ipv6"] == []


def test_lookup_gaierror_is_surfaced(monkeypatch):
    def boom(_host, _port):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", boom)
    result = dns_svc.lookup("does-not-exist.invalid")
    assert "Could not resolve" in result["error"]


def test_lookup_canonical_via_getnameinfo(monkeypatch):
    infos = _fake_addrinfo([(socket.AF_INET, "93.184.216.34")])
    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", lambda host, port: infos)
    monkeypatch.setattr(
        dns_svc.socket,
        "getnameinfo",
        lambda sockaddr, flags: ("example.com", ""),
    )
    result = dns_svc.lookup("example.com")
    assert result["canonical"] == "example.com"


def test_lookup_duplicates_deduped(monkeypatch):
    infos = _fake_addrinfo([(socket.AF_INET, "1.2.3.4"), (socket.AF_INET, "1.2.3.4")])
    monkeypatch.setattr(dns_svc.socket, "getaddrinfo", lambda host, port: infos)
    monkeypatch.setattr(
        dns_svc.socket,
        "getnameinfo",
        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, "")),
    )
    result = dns_svc.lookup("example.com")
    assert result["ipv4"] == ["1.2.3.4"]


def test_dns_route_valid(client):
    # Mock both getaddrinfo AND getnameinfo so no OS resolver is contacted.
    infos = _fake_addrinfo([(socket.AF_INET, "1.2.3.4")])

    def fake_addrinfo(_host, _port=0, *_a, **_k):
        return infos

    def fake_getnameinfo(*_a, **_k):
        raise socket.gaierror(socket.EAI_NONAME, "")

    with (
        mock.patch("socket.getaddrinfo", fake_addrinfo),
        mock.patch("socket.getnameinfo", fake_getnameinfo),
    ):
        resp = client.post("/tools/dns", data={"target": "example.com"})
        assert resp.status_code == 200
        assert b'data-tool-result="dns"' in resp.data


def test_dns_route_invalid_host_rejected(client):
    resp = client.post("/tools/dns", data={"target": "not a valid host!"})
    assert resp.status_code == 400
