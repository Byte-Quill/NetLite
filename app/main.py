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

from flask import Flask, jsonify, request

from . import __version__
from .config import Config


def _secure_headers(response):
    """Attach baseline security headers to every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    # Private caching for HTML; smalle and efficient for a local utility.
    response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
    return response


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