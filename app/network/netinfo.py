"""Local network information service.

Reads hostname, IP addresses, and (best-effort) default gateway.  All data is
read-only; never modifies the system and never requires root.
"""

from __future__ import annotations

import socket

from ..config import Config

#: Files read for best-effort network info; override in tests.
_PROC_ROUTE = "/proc/net/route"
_RESOLV_CONF = "/etc/resolv.conf"


def _default_gateway_linux() -> str | None:
    """Read the default IPv4 gateway from /proc/net/route (Linux only)."""
    try:
        with open(_PROC_ROUTE, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[0] != "Iface" and parts[1] == "00000000":
                    # Gateway is in little-endian hex.
                    gw_hex = parts[2]
                    if len(gw_hex) == 8:
                        octets = [int(gw_hex[i : i + 2], 16) for i in (6, 4, 2, 0)]
                        return ".".join(str(o) for o in octets)
    except (OSError, ValueError):
        pass
    return None


def collect(config: Config) -> dict:
    """Collect local network information with graceful fallbacks.

    Every field is best-effort: any failure degrades to a ``None`` / empty
    value rather than an exception, so the UI always renders something sane.
    """
    info: dict = {"hostname": socket.gethostname()}

    # Local addresses via gethostbyname_ex (primary + aliases + addresses).
    try:
        primary, aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
        info["primary_hostname"] = primary
        info["aliases"] = aliases
        info["local_addresses"] = addresses
    except (socket.gaierror, OSError):
        info["primary_hostname"] = None
        info["aliases"] = []
        info["local_addresses"] = []

    # IPv6 support is best-effort.
    try:
        info["ipv6_supported"] = socket.has_ipv6
    except AttributeError:
        info["ipv6_supported"] = False

    # Default gateway (Linux /proc).  Returns None when not detectable.
    info["default_gateway"] = _default_gateway_linux() or None

    # DNS configuration where available (resolv.conf).
    info["dns_servers"] = _read_resolv_conf()

    # FQDN of this machine if resolvable.
    try:
        info["fqdn"] = socket.getfqdn() or None
    except OSError:
        info["fqdn"] = None

    return _present(info)


def _present(info: dict) -> dict:
    """Normalize values into template-friendly strings.

    Lists are joined with ', ', booleans become 'yes'/'no', and other
    non-string scalars are stringified.  ``None`` stays None (the template
    renders an em-dash).
    """
    out: dict = {}
    for key, value in info.items():
        if isinstance(value, bool):
            out[key] = "yes" if value else "no"
        elif isinstance(value, (list, tuple)):
            out[key] = ", ".join(str(v) for v in value) if value else None
        elif isinstance(value, str):
            out[key] = value or None
        elif value is None:
            out[key] = None
        else:
            out[key] = str(value)
    return out


def _read_resolv_conf() -> list[str]:
    servers: list[str] = []
    try:
        with open(_RESOLV_CONF, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


__all__ = ["_default_gateway_linux", "_read_resolv_conf", "collect"]
