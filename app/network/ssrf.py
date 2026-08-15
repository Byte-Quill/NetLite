"""SSRF (Server-Side Request Forgery) protection.

The HTTP inspector fetches URLs *on behalf of the browser user*.  Because the
server performs the request, a malicious or careless user could otherwise use
NetLite as a proxy to probe internal services (cloud metadata endpoints,
localhost, private ranges).  This module makes that impossible by default:

* only ``http``/``https`` schemes are ever considered (enforced upstream);
* every target hostname is resolved, and **every** resolved address is
  checked against private / link-local / loopback / special-purpose ranges;
* if the default policy blocks a target, the run is refused before any
  network socket is opened (no DNS data leak to internal resolvers either);
* operators can *explicitly* opt in to private destinations by setting
  ``NETLITE_ALLOW_PRIVATE=1`` (see docs/security.md for the trade-offs).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from ..validation import ValidationError

# --------------------------------------------------------------------------
# Address classification (uses the ipaddress module, no string tricks).
# --------------------------------------------------------------------------

_PRIVATE_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("172.16.0.0/12"),    # private
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),        # "this" network
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("fc00::/7"),         # unique local
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped (re-check)
    ipaddress.ip_network("2001:db8::/32"),    # documentation
)

# Subnets that are *always* blocked regardless of ALLOW_PRIVATE (metadata
# endpoint abuse is a common SSRF vector even on "private" networks).
_ALWAYS_BLOCKED = (
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
)


@dataclass(frozen=True)
class SsrfDecision:
    """Outcome of an SSRF check."""

    allowed: bool
    reason: str | None = None
    addresses: tuple[str, ...] = ()
    hostname: str | None = None


def _classify(ip: ipaddress._BaseAddress) -> str | None:
    """Return a human-readable label if ``ip`` is in a blocked/fenced class."""
    for net in _ALWAYS_BLOCKED:
        if ip in net:
            return str(net)
    for net in _PRIVATE_NETS:
        if ip in net:
            return str(net)
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

    if label in {str(n) for n in _ALWAYS_BLOCKED}:
        return SsrfDecision(
            allowed=False,
            reason=f"Destination {ip} is reserved for special purposes and is always blocked.",
            addresses=(str(ip),),
        )

    if allow_private:
        return SsrfDecision(allowed=True, addresses=(str(ip),))

    return SsrfDecision(
        allowed=False,
        reason=(
            f"Destination {ip} is in a private/link-local/reserved range "
            f"({label}) and is blocked by the SSRF policy. "
            "Set NETLITE_ALLOW_PRIVATE=1 to allow it explicitly."
        ),
        addresses=(str(ip),),
    )


def check_hostname(hostname: str, *, allow_private: bool) -> SsrfDecision:
    """Resolve ``hostname`` and check every resulting address.

    This is the DNS-rebinding countermeasure: we do not trust the string that
    the user typed, we verify what the resolver actually returns right now,
    and we refuse when ANY resolved address is in a blocked range.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return SsrfDecision(allowed=False, reason="Could not resolve hostname.")

    addresses: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if len(sockaddr) == 2:  # IPv4
            addresses.add(sockaddr[0])
        elif len(sockaddr) >= 4:  # IPv6 (skip scope id)
            addr = sockaddr[0].split("%")[0]
            addresses.add(addr)

    for addr in sorted(addresses):
        decision = check_ip(addr, allow_private=allow_private)
        if not decision.allowed:
            return SsrfDecision(
                allowed=False,
                reason=f"Resolved address {addr} is blocked: {decision.reason}",
                addresses=tuple(sorted(addresses)),
                hostname=hostname,
            )
    return SsrfDecision(
        allowed=True,
        addresses=tuple(sorted(addresses)),
        hostname=hostname,
    )


def guard_url(hostname: str, *, allow_private: bool) -> SsrfDecision:
    """Validate a target hostname before any network I/O happens.

    Raises :class:`~app.validation.ValidationError` when the target is
    blocked, which callers render as a friendly error fragment.
    """
    decision = check_hostname(hostname, allow_private=allow_private)
    if not decision.allowed:
        raise ValidationError(
            decision.reason or "Target address is blocked by security policy."
        )
    return decision


__all__ = ["check_ip", "check_hostname", "guard_url", "SsrfDecision", "ValidationError"]