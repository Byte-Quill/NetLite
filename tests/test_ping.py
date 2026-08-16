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

WINDOWS_OK_OUTPUT = """\
Pinging example.com [93.184.216.34] with 32 bytes of data:
Reply from 93.184.216.34: bytes=32 time=11ms TTL=57
Reply from 93.184.216.34: bytes=32 time=11ms TTL=57
Reply from 93.184.216.34: bytes=32 time=11ms TTL=57

Ping statistics for 93.184.216.34:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 11ms, Average = 11ms
"""

WINDOWS_UNREACHABLE_OUTPUT = """\
Pinging 10.255.255.1 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.255.255.1:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
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


def test_parse_windows_ok():
    result = ping_svc._parse_output("example.com", WINDOWS_OK_OUTPUT, sent=3)
    assert result["status"] == "ok"
    assert result["received"] == 3
    assert result["latency_ms"] == "11 ms"


def test_parse_windows_unreachable():
    result = ping_svc._parse_output("10.255.255.1", WINDOWS_UNREACHABLE_OUTPUT, sent=3)
    assert result["status"] == "unreachable"
    assert result["received"] == 0
    assert result["latency_ms"] is None


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
    monkeypatch.setattr(ping_svc.os, "name", "posix")
    monkeypatch.setattr(ping_svc.sys, "platform", "linux")

    result = ping_svc.run("example.com", timeout=3.0, count=3)

    assert called["cmd"][0] == "/usr/bin/ping"
    assert called["cmd"][1:] == ["-c", "3", "-W", "3", "example.com"]
    assert result["status"] == "ok"


def test_run_builds_macos_command(monkeypatch):
    """On macOS/BSD the -W flag takes milliseconds, unlike GNU/Linux seconds."""
    called = {}

    class FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(cmd, **_kwargs):
        called["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(ping_svc.shutil, "which", lambda _name: "/sbin/ping")
    monkeypatch.setattr(ping_svc.subprocess, "run", fake_run)
    monkeypatch.setattr(ping_svc.os, "name", "posix")
    monkeypatch.setattr(ping_svc.sys, "platform", "darwin")

    ping_svc.run("example.com", timeout=3.0, count=3)

    assert called["cmd"][1:] == ["-c", "3", "-W", "3000", "example.com"]


def test_run_builds_windows_command(monkeypatch):
    """On Windows the flags must be -n (count) and -w (timeout in ms)."""
    called = {}

    class FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(cmd, **_kwargs):
        called["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(ping_svc.shutil, "which", lambda _name: "C:\\Windows\\ping.exe")
    monkeypatch.setattr(ping_svc.subprocess, "run", fake_run)
    monkeypatch.setattr(ping_svc.os, "name", "nt")

    ping_svc.run("example.com", timeout=3.0, count=3)

    assert called["cmd"][1:] == ["-n", "3", "-w", "3000", "example.com"]


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
