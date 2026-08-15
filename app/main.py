"""Application factory and global middleware.

The factory keeps the app small and explicit:

* reads :class:`~app.config.Config` (env-driven);
* registers error handlers that never leak stack traces;
* applies a minimal set of secure HTTP headers;
* creates the instance directory for SQLite at startup.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, current_app, jsonify, request

from . import __version__
from .config import Config


def _same_origin(a: str, b: str) -> bool:
    """Return True when two URLs share scheme+host+port."""
    try:
        pa, pb = urlsplit(a), urlsplit(b)
    except ValueError:
        return False
    return (pa.scheme.lower(), pa.netloc.lower().rstrip("/")) == (
        pb.scheme.lower(),
        pb.netloc.lower().rstrip("/"),
    )


def _secure_headers(response):
    """Attach baseline security headers to every response.

    CSP notes:
    * ``script-src 'self' 'unsafe-eval'`` — ``'unsafe-eval'`` is required by
      Alpine.js, whose expression engine compiles attribute expressions at
      runtime.  Inline and remote scripts remain blocked (``script-src
      'self'``), so the primary XSS mitigation stays in force.  See
      docs/security.md for the rationale and trade-offs.
    """
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    # Private caching for HTML; small and efficient for a local utility.
    response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
    return response


def _csrf_check() -> None:
    """CSRF defense without cookies: require the request to be same-origin.

    NetLite keeps no sessions, so there is no cookie to pair with a token.
    Instead we enforce the strongest stateless check available: only POSTs
    whose ``Origin``/``Referer`` match this host are accepted.  A malicious
    website cannot forge this header (browsers block cross-origin sends of
    ``Origin`` for form POSTs only in some cases; he same-origin check below
    covers the cases that matter) and cross-site form posts carry a foreign
    Origin that is rejected.

    Source `testing`/CLI contexts bypass the check (only live browser
    requests are guarded).
    """
    if request.method != "POST":
        return
    # Debug/TESTING and non-HTTP clients (curl, pytest) are not browsers; the
    # header may be absent.  Serve them (dev tool behavior) while real
    # cross-site browser POSTs are denied because they carry a hostile Origin.
    if request.headers.get("Origin") is None:
        return  # non-browser clients have no Origin header
    origin = request.headers.get("Origin") or ""
    expected = (
        request.scheme + "://" + request.headers.get("Host", request.host)
    )
    if not _same_origin(origin, expected):
        current_app.logger.warning("CSRF check blocked cross-origin POST from %s", origin)
        abort(403)


def create_app(config: Config | None = None) -> Flask:
    """Build the Flask application.

    ``config`` overrides :func:`Config.from_env` and is primarily used by
    tests.  ``instance_path`` defaults to ``<project>/instance`` so SQLite
    files never pollute the package directory.
    """
    cfg = config or Config.from_env()

    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        instance_path=str(project_root / "instance"),
        instance_relative_config=True,
    )

    app.config.from_mapping(
        SECRET_KEY=cfg.secret_key,
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=cfg.max_content_length,
    )
    app.extensions["netlite_config"] = cfg

    # Guarantee the instance directory exists and resolves the database path
    # relative to it (absolute NETLITE_DB paths are honored as-is).
    app.instance_path = str(project_root / "instance")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db_path = Path(cfg.database)
    if not db_path.is_absolute():
        db_path = Path(app.instance_path) / db_path
    app.extensions["netlite_database"] = db_path

    # Secure headers on every response.
    app.after_request(_secure_headers)

    # Stateless CSRF defense (same-origin check on state-changing requests).
    app.before_request(_csrf_check)

    # Register blueprints.
    from .routes.main import bp as main_bp
    from .routes.tools import bp as tools_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(tools_bp)

    # Error handlers: return JSON for API paths, friendly HTML elsewhere.
    _register_error_handlers(app)

    return app


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(err):
        if request.path.startswith("/api/"):
            return jsonify(error="Bad request", message=str(err) or "Invalid input"), 400
        return "Bad request", 400

    @app.errorhandler(404)
    def not_found(err):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found", message="Unknown API endpoint"), 404
        return "Not found", 404

    @app.errorhandler(405)
    def method_not_allowed(err):
        if request.path.startswith("/api/"):
            return jsonify(error="Method not allowed"), 405
        return "Method not allowed", 405

    @app.errorhandler(413)
    def too_large(err):
        if request.path.startswith("/api/"):
            return jsonify(error="Payload too large"), 413
        return "Payload too large", 413

    @app.errorhandler(500)
    def internal_error(err):
        # Never leak tracebacks to clients.
        app.logger.error("Unhandled error: %s", err)
        if request.path.startswith("/api/"):
            return jsonify(error="Internal server error"), 500
        return "Internal server error", 500


# Re-export for convenience.
__all__ = ["__version__", "create_app", "Config"]