"""Application factory.

Composes the pieces of the app: configuration, storage, middleware, and
blueprints.  Each concern lives in its own module so the factory stays a
thin, readable wiring point:

* :mod:`app.config` — env-driven settings;
* :mod:`app.extensions` — typed access to app-level values;
* :mod:`app.middleware` — secure headers, CSRF defense, error handlers;
* :mod:`app.tools` — declarative registry of diagnostic tools;
* :mod:`app.routes` — page and tool blueprints.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from . import __version__
from .config import Config
from .extensions import set_config, set_database
from .middleware import _csrf_check, _secure_headers, register_error_handlers


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
        MAX_CONTENT_LENGTH=cfg.max_content_length,
    )
    set_config(app, cfg)

    # Resolve the database path relative to the instance directory
    # (absolute NETLITE_DB paths are honored as-is).
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db_path = Path(cfg.database)
    if not db_path.is_absolute():
        db_path = Path(app.instance_path) / db_path
    set_database(app, db_path)

    # Cross-cutting HTTP concerns.
    app.after_request(_secure_headers)
    app.before_request(_csrf_check)
    register_error_handlers(app)

    # Blueprints.
    from .routes.main import bp as main_bp
    from .routes.tools import bp as tools_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(tools_bp)

    return app


# Re-export for convenience.
__all__ = ["Config", "__version__", "create_app"]
