"""Local network information service — cross-platform (Windows/macOS/Linux).

Reads hostname, IP addresses, and (best-effort) default gateway + DNS
servers.  All data is read-only; never modifies the system and never requires
root.  Gateway/DNS discovery is platform-specific and always best-effort:
any failure degrades to ``None`` / empty rather than raising.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys

#: Files read for best-effort network info; override in tests.
_PROC_ROUTE = "/proc/net/route"
_RESOLV_CONF = "/etc/resolv.conf"

#: Bound for helper subprocesses (netstat / ipconfig) so they can't hang.
_SUBPROC_TIMEOUT = 5.0

# Windows "Default Gateway . . . . . . . . . : 192.168.1.1"
_WIN_GATEWAY_RE = re.compile(r"Default Gateway[^:]*:\s*([0-9a-fA-F.:]+)")
# Windows "DNS Servers . . . . . . . . . . . : 1.1.1.1"
_WIN_DNS_RE = re.compile(r"DNS Servers[^:]*:\s*([0-9a-fA-F.:]+)")


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


def _default_gateway_macos() -> str | None:
    """Read the default IPv4 gateway via ``netstat -rn`` (macOS/BSD)."""
    binary = shutil.which("netstat")
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "-rn", "-f", "inet"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_SUBPROC_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        # "default  192.168.1.1  UGSc  en0"
        if parts and parts[0] == "default" and len(parts) >= 2:
            return parts[1]
    return None


def _default_gateway_windows() -> str | None:
    """Read the default IPv4 gateway via ``ipconfig`` (Windows)."""
    binary = shutil.which("ipconfig")
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_SUBPROC_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    match = _WIN_GATEWAY_RE.search(proc.stdout or "")
    return match.group(1) if match else None


def _default_gateway() -> str | None:
    """Dispatch to the platform-appropriate gateway reader."""
    if sys.platform.startswith("linux"):
        return _default_gateway_linux()
    if sys.platform == "darwin":
        return _default_gateway_macos()
    if sys.platform == "win32":
        return _default_gateway_windows()
    return None


def _read_resolv_conf() -> list[str]:
    """Read nameservers from /etc/resolv.conf (Linux/macOS)."""
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


def _dns_servers_windows() -> list[str]:
    """Read DNS servers via ``ipconfig /all`` (Windows)."""
    binary = shutil.which("ipconfig")
    if binary is None:
        return []
    try:
        proc = subprocess.run(
            [binary, "/all"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_SUBPROC_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    return [m.group(1) for m in _WIN_DNS_RE.finditer(proc.stdout or "")]


def _dns_servers() -> list[str]:
    """Dispatch to the platform-appropriate DNS-server reader."""
    if sys.platform == "win32":
        return _dns_servers_windows()
    return _read_resolv_conf()


def collect() -> dict:
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

    # Default gateway (platform-specific).  Returns None when not detectable.
    info["default_gateway"] = _default_gateway() or None

    # DNS configuration where available (platform-specific).
    info["dns_servers"] = _dns_servers()

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


__all__ = [
    "_default_gateway",
    "_default_gateway_linux",
    "_default_gateway_macos",
    "_default_gateway_windows",
    "_dns_servers",
    "_dns_servers_windows",
    "_read_resolv_conf",
    "collect",
]
