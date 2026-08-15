"""Tool endpoints.

Each tool has a single POST route that validates input, invokes the
corresponding network service, and returns an HTMX-compatible HTML fragment
injected into ``#result``.

ALL network operations run inside the bounded runner (see
:mod:`app.services.runner`) so a hang can never block the worker thread
indefinitely.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, render_template, request

from ..db import add_history, prune_history
from ..services import runner
from ..services.dispatch import run_tool
from ..validation import ValidationError

bp = Blueprint("tools", __name__)


def _form_value(name: str) -> str:
    """Read a form field, stripping whitespace and enforcing length."""
    raw = (request.form.get(name) or "").strip()
    if len(raw) > 512:
        raise ValidationError("Input is too long.")
    return raw


def _record(slug: str, target: str, status: str, summary: str) -> None:
    """Persist one history record, then prune to the retention cap."""
    cfg = current_app.extensions["netlite_config"]
    db_path = current_app.extensions["netlite_database"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        add_history(db_path, slug, target, status, now, summary)
        prune_history(db_path, cfg.max_history)
    except Exception:  # history must never break a diagnostic
        current_app.logger.warning("failed to record history", exc_info=True)


def _summary(slug: str, result: dict) -> str:
    """Build a short, non-sensitive summary string for the history table."""
    status = result.get("status", "")
    if slug == "ping":
        return f"{status}: {result.get('received', 0)}/{result.get('sent', 0)} pkt"
    if slug == "dns":
        n4 = len(result.get("ipv4", []) or [])
        n6 = len(result.get("ipv6", []) or [])
        return f"{status or 'resolved'}: {n4} IPv4, {n6} IPv6"
    if slug == "tcp":
        return f"{result.get('status', '')}: port {result.get('port', '')} {result.get('detail', '')}"
    if slug == "http":
        code = result.get("status_code")
        if code:
            return f"HTTP {code}"
        error = result.get("error")
        return f"error: {error[:60]}" if error else status
    if slug == "netinfo":
        return f"host {result.get('hostname', '')}"
    return status


def _run_and_render(slug: str, target: str, extra: dict | None = None):
    """Validate, run the tool, render the result fragment, record history."""
    try:
        result = run_tool(slug, target=target, config=current_app.extensions["netlite_config"], extra=extra or {})
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html",
            slug=slug,
            message=str(exc),
        ), 400
    except runner.ToolTimeout as exc:
        _record(slug, target, "timeout", str(exc)[:120])
        return render_template(
            "tools/partials/_result_error.html",
            slug=slug,
            message=str(exc),
        ), 408
    except Exception:  # never leak internals to the client
        current_app.logger.exception("tool %s failed", slug)
        return render_template(
            "tools/partials/_result_error.html",
            slug=slug,
            message="The tool failed unexpectedly.",
        ), 500

    status = result.get("status", "done")
    _record(slug, target, status, _summary(slug, result))
    return render_template(
        f"tools/partials/_result_{slug}.html",
        slug=slug,
        result=result,
    )


@bp.post("/tools/ping")
def tool_ping():
    try:
        target = _form_value("target")
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html", slug="ping", message=str(exc)
        ), 400
    return _run_and_render("ping", target)


@bp.post("/tools/dns")
def tool_dns():
    try:
        target = _form_value("target")
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html", slug="dns", message=str(exc)
        ), 400
    return _run_and_render("dns", target)


@bp.post("/tools/tcp")
def tool_tcp():
    try:
        target = _form_value("target")
        port = _form_value("port")
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html", slug="tcp", message=str(exc)
        ), 400
    return _run_and_render("tcp", target, extra={"port": port})


@bp.post("/tools/http")
def tool_http():
    try:
        target = _form_value("target")
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html", slug="http", message=str(exc)
        ), 400
    return _run_and_render("http", target)


@bp.post("/tools/netinfo")
def tool_netinfo():
    return _run_and_render("netinfo", "")
