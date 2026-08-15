"""Dispatch a tool request to its network service."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..validation import ValidationError, parse_port
from .runner import ToolTimeout, run_with_timeout


@dataclass(frozen=True)
class ToolRequest:
    """A validated tool invocation."""

    slug: str
    target: str
    config: Config
    port: int | None = None
    timeout: float | None = None


def run_tool(slug: str, *, target: str, config: Config, extra: dict | None = None) -> dict:
    """Validate and execute one tool, returning a plain dict result.

    The result dict only contains JSON-serializable, HTML-escaped-safe data;
    templates render it with Jinja autoescaping.
    """
    extra = extra or {}
    if slug == "ping":
        from ..network import ping as svc

        host = _require_host(target)

        def _ping():
            return svc.run(host, timeout=config.ping_timeout)

        return run_with_timeout(_ping, config.ping_timeout + svc.estimate_duration(config.ping_timeout) + 1.0)

    if slug == "dns":
        from ..network import dns as svc

        host = _require_host(target)
        return svc.lookup(host)

    if slug == "tcp":
        from ..network import tcp as svc

        host = _require_host(target)
        port = parse_port(extra.get("port", ""))
        return svc.check(host, port, timeout=config.connect_timeout)

    if slug == "http":
        from ..network import http as svc

        return svc.inspect(target, config=config)

    if slug == "netinfo":
        from ..network import netinfo as svc

        return svc.collect(config=config)

    raise ValidationError(f"Unknown tool: {slug!r}")


def _require_host(target: str) -> str:
    from ..validation import normalize_hostname

    if not target:
        raise ValidationError("Target is required.")
    return normalize_hostname(target)


def _require_url(target: str) -> str:
    from ..validation import parse_url

    if not target:
        raise ValidationError("URL is required.")
    return parse_url(target).original


__all__ = ["run_tool", "ToolRequest", "ToolTimeout"]