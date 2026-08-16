"""Tool endpoints.

Each tool from the registry (:mod:`app.tools`) gets a POST route that reads
its form fields, invokes the corresponding network service, and returns an
HTMX-compatible HTML fragment injected into ``#result``.  All network
operations run inside the bounded runner so a hang can never block the
worker thread indefinitely.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Blueprint, current_app, render_template, request

from ..db import add_history, prune_history
from ..extensions import get_config, get_database
from ..services import runner
from ..services.dispatch import run_tool
from ..tools import TOOLS
from ..validation import MAX_TARGET_LENGTH, ValidationError

bp = Blueprint("tools", __name__)


def _form_value(name: str) -> str:
    """Read a form field, stripping whitespace and enforcing length."""
    raw = (request.form.get(name) or "").strip()
    if len(raw) > MAX_TARGET_LENGTH:
        raise ValidationError("Input is too long.")
    return raw


def _record(slug: str, target: str, status: str, summary: str) -> None:
    """Persist one history record, then prune to the retention cap."""
    now = datetime.now(UTC).isoformat(timespec="seconds")
    try:
        add_history(
            get_database(current_app),
            slug,
            target,
            status,
            summary=summary,
            timestamp=now,
        )
        prune_history(get_database(current_app), get_config(current_app).max_history)
    except Exception:  # history must never break a diagnostic
        current_app.logger.warning("failed to record history", exc_info=True)


def _run_and_render(tool, target: str, extra: dict | None = None):
    """Validate, run the tool, render the result fragment, record history."""
    try:
        result = run_tool(
            tool.slug, target=target, config=get_config(current_app), extra=extra or {}
        )
    except ValidationError as exc:
        return render_template(
            "tools/partials/_result_error.html",
            slug=tool.slug,
            message=str(exc),
        ), 400
    except runner.ToolTimeout as exc:
        _record(tool.slug, target, "timeout", str(exc)[:120])
        return render_template(
            "tools/partials/_result_error.html",
            slug=tool.slug,
            message=str(exc),
        ), 408
    except Exception:  # never leak internals to the client
        current_app.logger.exception("tool %s failed", tool.slug)
        return render_template(
            "tools/partials/_result_error.html",
            slug=tool.slug,
            message="The tool failed unexpectedly.",
        ), 500

    status = result.get("status", "done")
    _record(tool.slug, target, status, tool.summary(result))
    return render_template(
        f"tools/partials/_result_{tool.slug}.html",
        slug=tool.slug,
        result=result,
    )


def _tool_route(tool):
    """Build the POST handler for one registered tool."""

    def handler():
        try:
            target = _form_value("target")
            extra = {"port": _form_value("port")} if tool.needs_port else {}
        except ValidationError as exc:
            return render_template(
                "tools/partials/_result_error.html", slug=tool.slug, message=str(exc)
            ), 400
        return _run_and_render(tool, target, extra)

    handler.__name__ = f"tool_{tool.slug}"
    return handler


for _tool in TOOLS.values():
    bp.add_url_rule(
        f"/tools/{_tool.slug}",
        f"tool_{_tool.slug}",
        _tool_route(_tool),
        methods=["POST"],
    )
