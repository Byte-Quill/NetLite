"""SSRF (Server-Side Request Forgery) protection.

The HTTP inspector fetches URLs *on behalf of the browser user*; without
protection it could be used to probe internal services (cloud metadata,
localhost, private ranges).  Every target hostname is resolved and every
resulting address is classified with :mod:`ipaddress` built-in properties;
any blocked address aborts the run before a socket opens.  Operators can opt
in to private destinations with ``NETLITE_ALLOW_PRIVATE=1``.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

#: Destinations blocked even with ALLOW_PRIVATE=1 (metadata endpoint abuse).
_ALWAYS_BLOCKED = (
    ipaddress.ip_network("0.0.0.0/8"),  # "this" network
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
    ipaddress.ip_network("::1/128"),  # loopback
)

#: CGNAT range (100.64/10) is not flagged by ipaddress properties.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class SsrfDecision:
    """Outcome of an SSRF check."""

    allowed: bool
    reason: str | None = None
    addresses: tuple[str, ...] = ()
    hostname: str | None = None


def _classify(ip: ipaddress._BaseAddress) -> str | None:
    """Label ``ip`` when it falls in a blocked/fenced range."""
    if any(ip in net for net in _ALWAYS_BLOCKED):
        return "reserved"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private or ip in _CGNAT:
        return "private"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return None


def check_ip(ip_text: str, *, allow_private: bool) -> SsrfDecision:
    """Check a single IP literal against the SSRF policy."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return SsrfDecision(allowed=False, reason="Invalid IP address.")

    label = _classify(ip)
    if label is None:
        return SsrfDecision(allowed=True, addresses=(str(ip),))
    if label == "reserved" or not allow_private:
        reason = (
            f"Destination {ip} is reserved for special purposes and is always blocked."
            if label == "reserved"
            else f"Destination {ip} is in a {label} range and is blocked by the SSRF policy. "
            "Set NETLITE_ALLOW_PRIVATE=1 to allow it explicitly."
        )
        return SsrfDecision(allowed=False, reason=reason, addresses=(str(ip),))
    return SsrfDecision(allowed=True, addresses=(str(ip),))


def check_hostname(hostname: str, *, allow_private: bool) -> SsrfDecision:
    """Resolve ``hostname`` and check every resulting address.

    This is the DNS-rebinding countermeasure: we verify what the resolver
    returns right now and refuse when ANY address is in a blocked range.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return SsrfDecision(allowed=False, reason="Could not resolve hostname.")

    addresses = {sockaddr[0].split("%")[0] for _f, _t, _p, _c, sockaddr in infos}
    for addr in sorted(addresses):
        decision = check_ip(addr, allow_private=allow_private)
        if not decision.allowed:
            return SsrfDecision(
                allowed=False,
                reason=f"Resolved address {addr} is blocked: {decision.reason}",
                addresses=tuple(sorted(addresses)),
                hostname=hostname,
            )
    return SsrfDecision(allowed=True, addresses=tuple(sorted(addresses)), hostname=hostname)


__all__ = ["SsrfDecision", "check_hostname", "check_ip"]
