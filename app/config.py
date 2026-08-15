"""Application configuration.

All settings are read from environment variables prefixed with ``NETLITE_``
and fall back to safe defaults.  Values are validated as they are read so a
misconfigured deployment fails fast at startup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# --- Defaults -------------------------------------------------------------

APP_NAME = "NetLite"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_SECRET_KEY = "dev-only-change-me"
DEFAULT_DB_NAME = "netlite.sqlite3"
DEFAULT_MAX_HISTORY = 100
DEFAULT_MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MiB of form data

# Network operation timeouts (seconds).  Every external operation must be
# bounded so no request can block indefinitely.
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_PING_TIMEOUT = 5.0
DEFAULT_DNS_TIMEOUT = None  # OS resolver; kept False-y meaning "OS default"

# HTTP inspector: cap on the number of response bytes we consume.
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024  # 256 KiB

# SSRF policy.  ``ALLOW_PRIVATE`` must be explicitly set to "1" to permit
# connections to loopback / private / link-local networks.  See docs/security.md.
DEFAULT_ALLOW_PRIVATE = False


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(name: str, default: float, minimum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


@dataclass(frozen=True)
class Config:
    """Immutable application settings."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    secret_key: str = DEFAULT_SECRET_KEY
    database: Path = Path(DEFAULT_DB_NAME)
    max_history: int = DEFAULT_MAX_HISTORY
    max_content_length: int = DEFAULT_MAX_CONTENT_LENGTH

    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    read_timeout: float = DEFAULT_READ_TIMEOUT
    ping_timeout: float = DEFAULT_PING_TIMEOUT
    dns_timeout: float | None = DEFAULT_DNS_TIMEOUT

    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    allow_private: bool = DEFAULT_ALLOW_PRIVATE

    # Runtime sensible defaults that depend on the Flask app instance.
    instance_path: Path = field(default=Path("instance"), init=False, repr=False)

    @classmethod
    def from_env(cls) -> "Config":
        """Build a :class:`Config` from the process environment."""
        return cls(
            host=os.environ.get("NETLITE_HOST", DEFAULT_HOST),
            port=_env_int("NETLITE_PORT", DEFAULT_PORT, minimum=1),
            secret_key=os.environ.get("NETLITE_SECRET_KEY", DEFAULT_SECRET_KEY),
            database=Path(os.environ.get("NETLITE_DB", DEFAULT_DB_NAME)),
            max_history=_env_int("NETLITE_MAX_HISTORY", DEFAULT_MAX_HISTORY, minimum=1),
            max_content_length=_env_int(
                "NETLITE_MAX_CONTENT_LENGTH", DEFAULT_MAX_CONTENT_LENGTH, minimum=1024
            ),
            connect_timeout=_env_float(
                "NETLITE_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT, minimum=0.1
            ),
            read_timeout=_env_float(
                "NETLITE_READ_TIMEOUT", DEFAULT_READ_TIMEOUT, minimum=0.1
            ),
            ping_timeout=_env_float(
                "NETLITE_PING_TIMEOUT", DEFAULT_PING_TIMEOUT, minimum=0.1
            ),
            max_response_bytes=_env_int(
                "NETLITE_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES, minimum=1024
            ),
            allow_private=_env_bool("NETLITE_ALLOW_PRIVATE", DEFAULT_ALLOW_PRIVATE),
        )