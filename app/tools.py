"""Declarative registry of diagnostic tools.

Every tool is declared exactly once here: its dashboard card (name,
description, icon), its input validation, its network service call, its
history summary, and its timeout budget.  Dashboard rendering, POST routes,
dispatch, and history records are all derived from :data:`TOOLS`, so adding a
new diagnostic tool only requires:

1. a pure-logic module under :mod:`app.network` that returns a result dict;
2. one :class:`Tool` entry in this module;
3. ``*_form.html`` and ``_result_*.html`` partials under ``tools/partials/``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .config import Config
from .validation import ValidationError, normalize_hostname, parse_port


def _require_host(target: str) -> str:
    if not target:
        raise ValidationError("Target is required.")
    return normalize_hostname(target)


def _validate_host(target: str, extra: dict) -> dict:
    return {"host": _require_host(target)}


def _validate_host_port(target: str, extra: dict) -> dict:
    return {
        "host": _require_host(target),
        "port": parse_port(str(extra.get("port", ""))),
    }


def _validate_url(target: str, extra: dict) -> dict:
    # The URL is validated inside http.inspect via parse_url; a bare hostname
    # would otherwise fail normalize_hostname's shape check.
    return {"url": target}


def _validate_none(target: str, extra: dict) -> dict:
    return {}


def _run_ping(params: dict, config: Config) -> dict:
    from .network import ping

    return ping.run(params["host"], timeout=config.ping_timeout)


def _run_dns(params: dict, config: Config) -> dict:
    from .network import dns

    return dns.lookup(params["host"])


def _run_tcp(params: dict, config: Config) -> dict:
    from .network import tcp

    return tcp.check(params["host"], params["port"], timeout=config.connect_timeout)


def _run_http(params: dict, config: Config) -> dict:
    from .network import http

    return http.inspect(params["url"], config=config)


def _run_netinfo(params: dict, config: Config) -> dict:
    from .network import netinfo

    return netinfo.collect()


def _summary_ping(result: dict) -> str:
    status = result.get("status", "")
    return f"{status}: {result.get('received', 0)}/{result.get('sent', 0)} pkt"


def _summary_dns(result: dict) -> str:
    status = result.get("status", "")
    n4 = len(result.get("ipv4", []) or [])
    n6 = len(result.get("ipv6", []) or [])
    return f"{status or 'resolved'}: {n4} IPv4, {n6} IPv6"


def _summary_tcp(result: dict) -> str:
    return f"{result.get('status', '')}: port {result.get('port', '')} {result.get('detail', '')}"


def _summary_http(result: dict) -> str:
    code = result.get("status_code")
    if code:
        return f"HTTP {code}"
    error = result.get("error")
    return f"error: {error[:60]}" if error else result.get("status", "")


def _summary_netinfo(result: dict) -> str:
    return f"host {result.get('hostname', '')}"


def _budget_ping(config: Config) -> float:
    from .network import ping

    return config.ping_timeout + ping.estimate_duration(config.ping_timeout) + 1.0


def _budget_default(config: Config) -> float:
    # read_timeout covers the longest single bounded operation; add a small
    # margin for resolution + response processing.
    return config.connect_timeout + config.read_timeout + 2.0


@dataclass(frozen=True)
class Tool:
    """One diagnostic tool.

    ``validate`` turns raw form values into validated params; ``run``
    executes the network service against those params and returns a result
    dict; ``summary`` renders a short non-sensitive history line from the
    result; ``budget`` is the outer wall-clock deadline for ``run``.
    """

    slug: str
    name: str
    description: str
    icon: str
    run: Callable[[dict, Config], dict]
    summary: Callable[[dict], str]
    validate: Callable[[str, dict], dict] = _validate_host
    needs_port: bool = False
    budget: Callable[[Config], float] = _budget_default


TOOLS: dict[str, Tool] = {
    tool.slug: tool
    for tool in (
        Tool(
            "ping",
            "Ping",
            "Check reachability and latency of a host.",
            "↦",
            run=_run_ping,
            summary=_summary_ping,
            budget=_budget_ping,
        ),
        Tool(
            "dns",
            "DNS Lookup",
            "Resolve a hostname to IPv4 and IPv6 addresses.",
            "ℹ",
            run=_run_dns,
            summary=_summary_dns,
        ),
        Tool(
            "tcp",
            "Port Check",
            "Test whether a TCP port is open on a host.",
            "⇅",
            run=_run_tcp,
            summary=_summary_tcp,
            validate=_validate_host_port,
            needs_port=True,
        ),
        Tool(
            "http",
            "HTTP Inspector",
            "Inspect headers and metadata of an HTTP/HTTPS URL.",
            "⛁",
            run=_run_http,
            summary=_summary_http,
            validate=_validate_url,
        ),
        Tool(
            "netinfo",
            "Local Network",
            "Show information about this machine's network.",
            "⚙",
            run=_run_netinfo,
            summary=_summary_netinfo,
            validate=_validate_none,
        ),
    )
}
