"""DNS lookup service using the operating system resolver."""

from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class DnsResult:
    """Result of a DNS lookup."""

    host: str
    ipv4: list[str]
    ipv6: list[str]
    canonical: str | None
    error: str | None


def lookup(host: str) -> dict:
    """Resolve ``host`` via the OS resolver.

    Returns a dict with ``ipv4``, ``ipv6``, ``canonical``, and ``error``
    fields.  Never raises; failures are surfaced as friendly result states.
    """
    ipv4: list[str] = []
    ipv6: list[str] = []
    canonical: str | None = None

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return {
            "host": host,
            "ipv4": [],
            "ipv6": [],
            "canonical": None,
            "error": f"Could not resolve host: {exc.strerror or exc}",
        }

    by_family: dict[int, set[str]] = {}
    for family, _, _, canon, sockaddr in infos:
        if family == socket.AF_INET and len(sockaddr) > 0:
            by_family.setdefault(socket.AF_INET, set()).add(sockaddr[0])
        elif family == socket.AF_INET6 and len(sockaddr) > 0:
            by_family.setdefault(socket.AF_INET6, set()).add(sockaddr[0])
        if canon and not canonical:
            canonical = canon
    ipv4 = sorted(by_family.get(socket.AF_INET, set()))
    ipv6 = sorted(by_family.get(socket.AF_INET6, set()))

    # Best-effort canonical hostname via reverse lookup of the first address.
    if not canonical and ipv4:
        try:
            canonical = socket.getnameinfo((ipv4[0], 0), socket.NI_NAMEREQD) or None
        except (socket.gaierror, OSError):
            canonical = None
    elif not canonical and ipv6:
        try:
            canonical = socket.getnameinfo((ipv6[0].split("%")[0], 0, 0, 0), socket.NI_NAMEREQD) or None
        except (socket.gaierror, OSError):
            canonical = None

    if not ipv4 and not ipv6:
        return {
            "host": host,
            "ipv4": [],
            "ipv6": [],
            "canonical": canonical,
            "error": "No addresses returned for this host.",
        }

    return {
        "host": host,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "canonical": canonical,
        "error": None,
    }


__all__ = ["DnsResult", "lookup"]