"""Input validation helpers.

Every user-supplied value that finds its way into a network operation is
validated here first.  The validators are strict by design: they raise
:class:`ValidationError` on anything that does not match the expected shape,
so callers can render a friendly error fragment instead of hitting the
network with garbage.

Security properties of this module:

* hostnames are validated with a conservative RFC 952/1123-style pattern
  and IDNA-normalized so punycode / unicode domains are handled safely;
* IP addresses are parsed with :mod:`ipaddress` (never string patterns);
* ports are restricted to the legal 1-65535 range;
* URLs are parsed with :mod:`urllib.parse` and restricted to http/https,
  with any fragment / query / userinfo stripped for network calls.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_HOST_LENGTH = 253
MAX_TARGET_LENGTH = 512
MAX_URL_LENGTH = 2048

# Letters, digits, hyphen-separated labels; conservative RFC 1035 shape.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_ALLOWED_SCHEMES = {"http", "https"}

# Canonical decimal port, 1-65535, no sign, no padding, no hex.
_PORT_RE = re.compile(r"[1-9][0-9]{0,4}")


class ValidationError(ValueError):
    """Raised when user input fails validation."""


@dataclass(frozen=True)
class ParsedURL:
    """A normalized, validated URL that is safe to pass to the network layer."""

    original: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    #: Reconstructed URL without fragment / userinfo / extra port.
    target: str


def normalize_hostname(host: str) -> str:
    """Validate and IDNA-normalize a hostname or bare IP string.

    Returns the ASCII (punycode) form.  Raises :class:`ValidationError`
    for empty, oversized, or structurally invalid input.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValidationError("Host is required.")
    host = host.strip().rstrip(".")
    if len(host) > MAX_HOST_LENGTH:
        raise ValidationError("Host is too long.")

    # If it parses as an IP literal, keep it verbatim (normalized).
    if looks_like_ip(host):
        return ip_address_canonical(host)

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise ValidationError("Invalid hostname.") from None

    if not _HOSTNAME_RE.match(ascii_host):
        raise ValidationError("Invalid hostname.")
    return ascii_host


def looks_like_ip(value: str) -> bool:
    """Return True if ``value`` is a valid IPv4 or IPv6 literal."""
    stripped = value.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        stripped = stripped[1:-1]
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        return False
    return True


def ip_address_canonical(value: str) -> str:
    """Return the canonical string form of an IP literal, or None if invalid."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValidationError("Invalid IP address.") from None


def parse_port(value: str | int) -> int:
    """Validate a port number; raises :class:`ValidationError` if invalid.

    Accepts a canonical decimal string or int in 1..65535.  Rejects
    whitespace-padded, signed, hex, or otherwise ambiguous encodings so a
    string like ``" 443"`` or ``"+443"`` cannot slip past.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        port = value
    elif isinstance(value, str):
        if not _PORT_RE.fullmatch(value):
            raise ValidationError("Port must be a number between 1 and 65535.")
        port = int(value)
    else:
        raise ValidationError("Port must be a number between 1 and 65535.")
    if port < 1 or port > 65535:
        raise ValidationError("Port must be between 1 and 65535.")
    return port


def parse_url(value: str) -> ParsedURL:
    """Validate a URL for the HTTP inspector.

    Rejects schemes other than http/https, URLs without a host, and URLs
    whose hostname fails :func:`normalize_hostname`.  Returns a
    :class:`ParsedURL` with a clean, parameterless target.
    """
    if not isinstance(value, str):
        raise ValidationError("URL is required.")
    value = value.strip()
    if not value:
        raise ValidationError("URL is required.")
    if len(value) > MAX_URL_LENGTH:
        raise ValidationError("URL is too long.")

    # A bare hostname is a valid URL target only with an explicit scheme;
    # ``urlsplit`` would otherwise treat "example.com/x" as a path.
    if "://" not in value:
        raise ValidationError('URL must include a scheme, e.g. "https://example.com".')

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValidationError("Only http and https URLs are allowed.")
    if not parts.hostname:
        raise ValidationError("URL must include a hostname.")

    hostname = normalize_hostname(parts.hostname)

    port: int | None = None
    if parts.port is not None:
        port = parse_port(parts.port)

    netloc = hostname
    if port is not None:
        netloc = f"{hostname}:{port}"
    if parts.hostname and ":" in parts.hostname and not hostname.startswith("["):
        # IPv6 literal in netloc; urlsplit keeps the brackets.
        netloc = f"[{hostname}]"
        if port is not None:
            netloc = f"[{hostname}]:{port}"

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    return ParsedURL(
        original=value,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        target=f"{scheme}://{netloc}{path}",
    )