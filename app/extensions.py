"""Well-typed accessors for values stored on the Flask app.

``create_app`` stashes the resolved :class:`~app.config.Config` and the
absolute SQLite database path in ``app.extensions``; blueprints read them
back.  These accessors are the single place those key strings are spelled
out, and give callers real types instead of bare dict lookups.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from .config import Config

CONFIG_KEY = "netlite_config"
DATABASE_KEY = "netlite_database"


def set_config(app: Flask, cfg: Config) -> None:
    app.extensions[CONFIG_KEY] = cfg


def get_config(app: Flask) -> Config:
    return app.extensions[CONFIG_KEY]


def set_database(app: Flask, path: Path) -> None:
    app.extensions[DATABASE_KEY] = path


def get_database(app: Flask) -> Path:
    return app.extensions[DATABASE_KEY]
