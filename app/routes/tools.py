"""Tool endpoints.

Each tool has a single POST route that validates input, invokes the
corresponding network service, and returns an HTMX-compatible HTML fragment
injected into ``#result``.

ALL network operations run inside the bounded runner (see
:mod:`app.services.runner`) so a hang can never block the worker thread
indefinitely.
"""

from __future__ import annotations

from flask import Blueprint, current_app, render_template
from werkzeug.exceptions import BadRequest

from ..services import runner
from ..services.dispatch import run_tool
from ..validation import ValidationError

bp = Blueprint("tools", __name__)


def _form_value(name: str) -> str:
    """Read a form field, stripping whitespace and enforcing length."""
    raw = (current_app.request.form.get(name) or "").strip()
    if len(raw) > 512:
        raise ValidationError("Input is too long.")
    return raw


def _run_and_render(slug: str, target: str, extra: dict | None = None):
    """Validate, run the tool, and render its result fragment."""
    cfg = current_app.extensions["netlite_config"]
    try:
        result = run_tool(slug, target=target, config=cfg, extra=extra or {})
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html",
            slug=slug,
            message=str(exc),
        ), 400
    except runner.ToolTimeout as exc:
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