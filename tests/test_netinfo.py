"""Tests for the local network information service.

Only the pure helpers (gateway parsing, resolv.conf reading) are unit-tested
with temp files; ``collect`` delegates to OS APIs and is exercised for
graceful fallback behavior with monkeypatched sockets.
"""

from __future__ import annotations

from app.network import netinfo
from app.network.netinfo import (
    _default_gateway,
    _default_gateway_linux,
    _default_gateway_macos,
    _default_gateway_windows,
    _dns_servers,
    _dns_servers_windows,
    _present,
    _read_resolv_conf,
)


class _FakeProc:
    def __init__(self, stdout: str = ""):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def test_gateway_parsing(monkeypatch, tmp_path):
    route_file = tmp_path / "route"
    route_file.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("app.network.netinfo._PROC_ROUTE", str(route_file))
    assert _default_gateway_linux() == "192.168.1.1"


def test_gateway_no_default(monkeypatch, tmp_path):
    route_file = tmp_path / "route"
    route_file.write_text(
        "Iface\tDestination\tGateway \tFlags\neth0\t01000000\t0101A8C0\t0003\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(netinfo, "_PROC_ROUTE", str(route_file))
    assert _default_gateway_linux() is None


def test_gateway_missing_file(monkeypatch):
    monkeypatch.setattr(netinfo, "_PROC_ROUTE", "/nonexistent/route")
    assert _default_gateway_linux() is None


def test_resolv_conf(monkeypatch, tmp_path):
    rc = tmp_path / "resolv.conf"
    rc.write_text(
        "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch example.com\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(netinfo, "_RESOLV_CONF", str(rc))
    assert _read_resolv_conf() == ["1.1.1.1", "8.8.8.8"]


def test_resolv_missing(monkeypatch):
    monkeypatch.setattr(netinfo, "_RESOLV_CONF", "/nonexistent/resolv.conf")
    assert _read_resolv_conf() == []


def test_gateway_macos(monkeypatch):
    """macOS gateway comes from `netstat -rn` (default route line)."""
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: "/usr/sbin/netstat")
    monkeypatch.setattr(
        netinfo.subprocess,
        "run",
        lambda *a, **k: _FakeProc(
            "Routing tables\n\ndefault  192.168.1.1  UGSc  en0\n"
            "127.0.0.1  localhost  UH  lo0\n"
        ),
    )
    assert _default_gateway_macos() == "192.168.1.1"


def test_gateway_macos_no_binary(monkeypatch):
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: None)
    assert _default_gateway_macos() is None


def test_gateway_windows(monkeypatch):
    """Windows gateway comes from `ipconfig` output."""
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: "C:\\Windows\\ipconfig.exe")
    monkeypatch.setattr(
        netinfo.subprocess,
        "run",
        lambda *a, **k: _FakeProc(
            "Ethernet adapter Ethernet:\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        ),
    )
    assert _default_gateway_windows() == "192.168.1.1"


def test_gateway_windows_no_binary(monkeypatch):
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: None)
    assert _default_gateway_windows() is None


def test_dns_windows(monkeypatch):
    """Windows DNS servers come from `ipconfig /all` output."""
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: "C:\\Windows\\ipconfig.exe")
    monkeypatch.setattr(
        netinfo.subprocess,
        "run",
        lambda *a, **k: _FakeProc(
            "Ethernet adapter Ethernet:\n"
            "   DNS Servers . . . . . . . . . . . : 1.1.1.1\n"
            "                                       8.8.8.8\n"
        ),
    )
    assert _dns_servers_windows() == ["1.1.1.1"]


def test_dns_windows_no_binary(monkeypatch):
    monkeypatch.setattr(netinfo.shutil, "which", lambda _name: None)
    assert _dns_servers_windows() == []


def test_gateway_dispatch_linux(monkeypatch):
    monkeypatch.setattr(netinfo.sys, "platform", "linux")
    monkeypatch.setattr(netinfo, "_default_gateway_linux", lambda: "10.0.0.1")
    assert _default_gateway() == "10.0.0.1"


def test_gateway_dispatch_darwin(monkeypatch):
    monkeypatch.setattr(netinfo.sys, "platform", "darwin")
    monkeypatch.setattr(netinfo, "_default_gateway_macos", lambda: "10.0.0.1")
    assert _default_gateway() == "10.0.0.1"


def test_gateway_dispatch_windows(monkeypatch):
    monkeypatch.setattr(netinfo.sys, "platform", "win32")
    monkeypatch.setattr(netinfo, "_default_gateway_windows", lambda: "10.0.0.1")
    assert _default_gateway() == "10.0.0.1"


def test_gateway_dispatch_unknown_platform(monkeypatch):
    monkeypatch.setattr(netinfo.sys, "platform", "freebsd13")
    assert _default_gateway() is None


def test_dns_dispatch_windows(monkeypatch):
    monkeypatch.setattr(netinfo.sys, "platform", "win32")
    monkeypatch.setattr(netinfo, "_dns_servers_windows", lambda: ["9.9.9.9"])
    assert _dns_servers() == ["9.9.9.9"]


def test_dns_dispatch_posix(monkeypatch, tmp_path):
    rc = tmp_path / "resolv.conf"
    rc.write_text("nameserver 1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(netinfo, "_RESOLV_CONF", str(rc))
    monkeypatch.setattr(netinfo.sys, "platform", "linux")
    assert _dns_servers() == ["1.1.1.1"]


def test_collect_graceful_fallback(monkeypatch):
    """If gethostbyname_ex fails, the result must still be renderable."""
    import socket

    monkeypatch.setattr(netinfo.socket, "gethostname", lambda: "host.local")
    monkeypatch.setattr(
        netinfo.socket,
        "gethostbyname_ex",
        lambda _n: (_ for _ in ()).throw(socket.gaierror(socket.EAI_NONAME, "")),
    )
    monkeypatch.setattr(netinfo.socket, "getfqdn", lambda: "host.local")

    result = netinfo.collect()
    assert result["hostname"] == "host.local"
    assert result["local_addresses"] is None
    assert result["primary_hostname"] is None


def test_present_normalizes_values():
    info = {
        "hostname": "x",
        "ipv6_supported": True,
        "aliases": ["a", "b"],
        "dns_servers": [],
        "fqdn": None,
    }
    out = _present(info)
    assert out["ipv6_supported"] == "yes"
    assert out["aliases"] == "a, b"
    assert out["dns_servers"] is None
    assert out["fqdn"] is None


def test_netinfo_route(client):
    resp = client.post("/tools/netinfo")
    assert resp.status_code == 200
    assert b'data-tool-result="netinfo"' in resp.data
