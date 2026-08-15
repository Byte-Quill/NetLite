"""TCP port checker.

Checks a single host + single port with a bounded connect timeout.  The host
is resolved through :func:`socket.getaddrinfo` and every address is tried in
order; a connection succeeds if ANY resolved address accepts the port.

This is intentionally a one-request-per-call design: no scanning, no ranges,
no multi-port sweeps.  Rate limiting can be layered on top of the route layer
later without touching this module.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

#: Connection timeout configured by the caller; TCP checks bound to this.
DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True)
class TcpResult:
    """Outcome of a single TCP port check."""

    host: str
    port: int
    status: str  # "open" | "closed" | "timeout" | "invalid"
    resolved: list[str] | None
    detail: str


def check(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Attempt a TCP connection to ``host:port``.

    Returns a dict with ``status`` one of ``open`` / ``closed`` / ``timeout``
    / ``invalid``.  ``invalid`` is reserved for hostile or malformed targets.
    """
    if port < 1 or port > 65535:
        return _invalid(host, port, "Port must be between 1 and 65535.")

    try:
        infos = socket.getaddrinfo(host, port)
    except socket.gaierror:
        return _invalid(host, port, "Could not resolve hostname.")

    # Prefer IPv4 first, then IPv6, to keep the open/closed semantics simple.
    infos.sort(key=lambda info: 0 if info[0] == socket.AF_INET else 1)
    resolved = sorted({info[4][0] for info in infos})

    last_error: str | None = None
    for family, socktype, proto, _, sockaddr in infos:
        if socktype != socket.SOCK_STREAM:
            continue
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex(sockaddr)
        except (socket.timeout, TimeoutError):
            return {
                "host": host,
                "port": port,
                "status": "timeout",
                "resolved": resolved,
                "detail": f"Connection timed out after {timeout}s.",
            }
        except OSError:
            last_error = "Connection failed."
            continue
        if result == 0:
            return {
                "host": host,
                "port": port,
                "status": "open",
                "resolved": resolved,
                "detail": f"Connection to {host}:{port} succeeded.",
            }
        last_error = "Connection refused."

    return {
        "host": host,
        "port": port,
        "status": "closed",
        "resolved": resolved,
        "detail": last_error or "No address accepted a connection.",
    }


def _invalid(host: str, port: int, detail: str) -> dict:
    return {
        "host": host,
        "port": port,
        "status": "invalid",
        "resolved": None,
        "detail": detail,
    }


__all__ = ["TcpResult", "check", "DEFAULT_TIMEOUT"]