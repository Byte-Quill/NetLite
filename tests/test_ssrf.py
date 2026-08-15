"""Tests for the SSRF (Server-Side Request Forgery) protection module."""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from app.network import ssrf
from app.validation import ValidationError

# --- IP classification -----------------------------------------------------

def test_public_ipv4_allowed():
    d = ssrf.check_ip("8.8.8.8", allow_private=False)
    assert d.allowed is True


def test_loopback_blocked():
    d = ssrf.check_ip("127.0.0.1", allow_private=False)
    assert d.allowed is False
    assert "loopback" in d.reason.lower() or "private" in d.reason.lower()


def test_private_ranges_blocked():
    for addr in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
        d = ssrf.check_ip(addr, allow_private=False)
        assert d.allowed is False, addr
        assert "private" in d.reason.lower()


def test_link_local_blocked():
    d = ssrf.check_ip("169.254.169.254", allow_private=False)
    assert d.allowed is False
    assert "reserved" in d.reason.lower() or "blocked" in d.reason.lower()


def test_always_blocked_metadata_even_when_private_allowed():
    # Cloud metadata endpoints stay blocked even with NETLITE_ALLOW_PRIVATE=1.
    d = ssrf.check_ip("169.254.169.254", allow_private=True)
    assert d.allowed is False


def test_ipv6_loopback_blocked():
    d = ssrf.check_ip("::1", allow_private=False)
    assert d.allowed is False


def test_ipv6_unique_local_blocked():
    d = ssrf.check_ip("fd00::1", allow_private=False)
    assert d.allowed is False


def test_public_ipv6_allowed():
    d = ssrf.check_ip("2606:2800:220:1:248:1893:25c8:1946", allow_private=False)
    assert d.allowed is True


def test_invalid_ip_rejected():
    d = ssrf.check_ip("not-an-ip", allow_private=False)
    assert d.allowed is False
    assert "invalid" in d.reason.lower()


def test_allow_private_opt_in():
    d = ssrf.check_ip("127.0.0.1", allow_private=True)
    assert d.allowed is True


# --- Hostname resolution ---------------------------------------------------

def test_hostname_resolving_to_private_blocked():
    with mock.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))],
    ):
        d = ssrf.check_hostname("internal.example", allow_private=False)
    assert d.allowed is False
    assert "10.0.0.5" in d.reason


def test_hostname_resolving_to_public_allowed():
    with mock.patch(
        "socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    ):
        d = ssrf.check_hostname("example.com", allow_private=False)
    assert d.allowed is True
    assert "93.184.216.34" in d.addresses


def test_hostname_dns_failure_blocked():
    def boom(_host, _port):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with mock.patch("socket.getaddrinfo", boom):
        d = ssrf.check_hostname("does-not-exist.invalid", allow_private=False)
    assert d.allowed is False


def test_guard_url_raises_for_private(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ValidationError):
        ssrf.guard_url("localhost", allow_private=False)
