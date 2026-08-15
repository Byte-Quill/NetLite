"""Tests for the ping diagnostic service.

The parser is exercised with representative GNU and BSD outputs; the binary
invocation path is covered by mocking ``subprocess`` so tests never depend on
a live network or a particular ping implementation.
"""

from __future__ import annotations

from unittest import mock

from app.network import ping as ping_svc

GNU_OK_OUTPUT = """\
PING example.com (93.184.216.34) 56(84) bytes of data.
64 bytes from 93.184.216.34: icmp_seq=1 ttl=57 time=11.2 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=57 time=10.9 ms
64 bytes from 93.184.216.34: icmp_seq=3 ttl=57 time=11.1 ms

--- example.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 10.883/11.066/11.200/0.128 ms
"""

BSD_OK_OUTPUT = """\
PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=57 time=11.204 ms
64 bytes from 93.184.216.34: icmp_seq=1 ttl=57 time=10.912 ms
64 bytes from 93.184.216.34: icmp_seq=2 ttl=57 time=11.034 ms

--- example.com ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.912/11.050/11.204/0.120 ms
"""

UNREACHABLE_OUTPUT = """\
PING 10.255.255.1 (10.255.255.1) 56(84) bytes of data.

--- 10.255.255.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2040ms
"""


def test_parse_gnu_ok():
    result = ping_svc._parse_output("example.com", GNU_OK_OUTPUT, sent=3)
    assert result["status"] == "ok"
    assert result["received"] == 3
    assert result["resolved"] == "93.184.216.34"
    assert result["latency_ms"] == "11.066 ms"
    assert result["details"] == "3/3 packets received"


def test_parse_bsd_ok():
    result = ping_svc._parse_output("example.com", BSD_OK_OUTPUT, sent=3)
    assert result["status"] == "ok"
    assert result["received"] == 3
    assert result["resolved"] == "93.184.216.34"
    assert result["latency_ms"] == "11.050 ms"


def test_parse_unreachable():
    result = ping_svc._parse_output("10.255.255.1", UNREACHABLE_OUTPUT, sent=3)
    assert result["status"] == "unreachable"
    assert result["received"] == 0
    assert result["latency_ms"] is None


def test_parse_name_resolution_error():
    output = "ping: example.invalid: Name or service not known"
    result = ping_svc._parse_output("example.invalid", output, sent=3)
    assert result["status"] == "error"
    assert "Could not resolve" in result["details"]


def test_run_invokes_binary_without_shell(monkeypatch):
    called = {}

    class FakeProc:
        stdout = GNU_OK_OUTPUT
        stderr = ""
        returncode = 0

    def fake_run(cmd, **_kwargs):
        called["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(ping_svc.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(ping_svc.subprocess, "run", fake_run)

    result = ping_svc.run("example.com", timeout=3.0, count=3)

    assert called["cmd"][0] == "/usr/bin/ping"
    assert called["cmd"][1:] == ["-c", "3", "-W", "3", "example.com"]
    assert result["status"] == "ok"


def test_run_missing_binary(monkeypatch):
    monkeypatch.setattr(ping_svc.shutil, "which", lambda _name: None)
    result = ping_svc.run("example.com")
    assert result["status"] == "error"
    assert "not available" in result["details"]


def test_run_timeout(monkeypatch):
    import subprocess

    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["ping"], timeout=1.0)

    monkeypatch.setattr(ping_svc.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(ping_svc.subprocess, "run", fake_run)
    result = ping_svc.run("example.com", timeout=1.0, count=3)
    assert result["status"] == "timeout"
    assert result["received"] == 0


def test_run_host_validated_at_dispatch(client):
    # A definitionally invalid hostname must never reach the binary.
    resp = client.post("/tools/ping", data={"target": "not a valid host!"})
    assert resp.status_code == 400
    assert b"result-error" in resp.data


def test_ping_route_valid(client):
    # Route works (validation passes); the service is mocked out via dispatch
    # so we avoid touching the real ping binary in tests.
    with mock.patch("app.network.ping.shutil.which", return_value=None):
        resp = client.post("/tools/ping", data={"target": "example.com"})
        assert resp.status_code == 200
        assert b'data-tool-result="ping"' in resp.data
