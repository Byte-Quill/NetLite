"""Core pages: dashboard, health endpoint, and history placeholder."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template

from .. import __version__
from ..db import list_history

bp = Blueprint("main", __name__)

#: Tools shown on the dashboard.  Each entry maps to a partial template and
#: a POST target under ``/tools/<slug>``.
TOOLS = [
    {
        "slug": "ping",
        "name": "Ping",
        "description": "Check reachability and latency of a host.",
        "icon": "↦",
    },
    {
        "slug": "dns",
        "name": "DNS Lookup",
        "description": "Resolve a hostname to IPv4 and IPv6 addresses.",
        "icon": "ℹ",
    },
    {
        "slug": "tcp",
        "name": "Port Check",
        "description": "Test whether a TCP port is open on a host.",
        "icon": "⇅",
    },
    {
        "slug": "http",
        "name": "HTTP Inspector",
        "description": "Inspect headers and metadata of an HTTP/HTTPS URL.",
        "icon": "⛁",
    },
    {
        "slug": "netinfo",
        "name": "Local Network",
        "description": "Show information about this machine's network.",
        "icon": "⚙",
    },
]


@bp.get("/")
def index():
    """Render the dashboard main page."""
    cfg = current_app.extensions["netlite_config"]
    return render_template(
        "dashboard.html",
        tools=TOOLS,
        version=__version__,
        max_history=cfg.max_history,
    )


@bp.get("/history")
def history():
    """Render the recent-diagnostics history page."""
    cfg = current_app.extensions["netlite_config"]
    records = list_history(cfg.database, cfg.max_history)
    return render_template(
        "history.html",
        records=records,
        max_history=cfg.max_history,
    )


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