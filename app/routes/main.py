"""Core pages: dashboard, health endpoint, and history."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template

from .. import __version__
from ..db import delete_history, list_history
from ..extensions import get_config, get_database
from ..tools import TOOLS

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    """Render the dashboard main page."""
    return render_template(
        "dashboard.html",
        tools=TOOLS.values(),
        version=__version__,
        max_history=get_config(current_app).max_history,
    )


@bp.get("/history")
def history():
    """Render the recent-diagnostics history page."""
    records = list_history(get_database(current_app), get_config(current_app).max_history)
    return render_template(
        "history.html",
        records=records,
        max_history=get_config(current_app).max_history,
    )


@bp.post("/history/<int:record_id>/delete")
def history_delete(record_id: int):
    """Delete a single history record (HTMX-friendly)."""
    deleted = delete_history(get_database(current_app), record_id)
    if not deleted:
        return "", 404
    # Return an out-of-band removal target so HTMX can drop the row.
    return f'<tr class="row-deleted" id="history-row-{record_id}" hx-swap-oob="outerHTML"></tr>'


@bp.get("/api/health")
def health():
    """Minimal health endpoint used by monitors and smoke tests."""
    return jsonify(
        {
            "status": "ok",
            "app": "netlite",
            "version": __version__,
        }
    )
