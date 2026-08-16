"""DNS lookup service using the operating system resolver."""

from __future__ import annotations

import socket

#: Common gai error codes → friendly messages (no raw OS text leakage).
_GAI_MSG = {
    socket.EAI_NONAME: "The hostname does not exist in DNS.",
    socket.EAI_AGAIN: "The nameserver temporarily failed; try again.",
    socket.EAI_NODATA: "The hostname has no address records.",
    socket.EAI_FAIL: "The nameserver returned a permanent failure.",
    socket.EAI_SERVICE: "The requested service is not available.",
}


def _friendly_gai_error(exc: socket.gaierror) -> str:
    """Return a friendly message for a gai error without leaking internals."""
    return _GAI_MSG.get(exc.errno, "A DNS resolution error occurred.")


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
            "error": f"Could not resolve host: {_friendly_gai_error(exc)}",
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
            host, _port = socket.getnameinfo((ipv4[0], 0), socket.NI_NAMEREQD)
            canonical = host or None
        except (socket.gaierror, OSError):
            canonical = None
    elif not canonical and ipv6:
        try:
            host, _port = socket.getnameinfo((ipv6[0].split("%")[0], 0, 0, 0), socket.NI_NAMEREQD)
            canonical = host or None
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


__all__ = ["lookup"]
