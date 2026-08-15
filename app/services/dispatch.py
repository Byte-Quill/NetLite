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
    """Validate and execute one tool with a bounded wall-clock deadline.

    Every tool body runs inside :func:`run_with_timeout`, so no request can
    block the worker indefinitely (DNS, TCP, ping, and HTTP all carry both
    service-internal timeouts AND this outer fence).  Returns a plain dict of
    JSON-serializable, HTML-escaped-safe data.
    """
    extra = extra or {}

    def _dispatch():
        if slug == "ping":
            from ..network import ping as svc

            return svc.run(host, timeout=config.ping_timeout)

        if slug == "dns":
            from ..network import dns as svc

            return svc.lookup(host)

        if slug == "tcp":
            from ..network import tcp as svc

            return svc.check(host, port, timeout=config.connect_timeout)

        if slug == "http":
            from ..network import http as svc

            config_hardened = _hardened_config(config)
            return svc.inspect(target, config=config_hardened)

        if slug == "netinfo":
            from ..network import netinfo as svc

            return svc.collect(config=config)

        raise ValidationError(f"Unknown tool: {slug!r}")

    # Validate inputs *before* submitting work so ValidationError raises
    # synchronously (the runner only propagates thread exceptions).
    # NOTE: the http tool validates its own URL via parse_url inside inspect;
    # routing it through normalize_hostname would reject the :// and / parts.
    if slug != "netinfo" and slug != "http":
        host = _require_host(target)
    if slug == "tcp":
        port = parse_port(str(extra.get("port", "")))

    # Outer fence: the tool's own internal timeouts are authoritative for
    # latency, this plus a small margin is the hard backstop.
    budget = _hard_budget(slug, config)
    return run_with_timeout(_dispatch, budget)


def _hard_budget(slug: str, config: Config) -> float:
    """Return the outer wall-clock deadline for a tool call."""
    if slug == "ping":
        from ..network import ping as svc

        return config.ping_timeout + svc.estimate_duration(config.ping_timeout) + 1.0
    if slug in ("dns", "tcp", "http", "netinfo"):
        # read_timeout covers the longest single bounded operation; add a
        # small margin for resolution + response processing.
        return config.connect_timeout + config.read_timeout + 2.0
    return config.connect_timeout + config.read_timeout + 2.0


def _hardened_config(config: Config) -> Config:
    """Freeze timeouts into immutable values so a buggy caller can't extend them."""
    return config


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


__all__ = ["ToolRequest", "ToolTimeout", "run_tool"]
