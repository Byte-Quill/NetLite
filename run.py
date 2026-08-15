"""Development entry point for NetLite.

Usage:
    python run.py [--host HOST] [--port PORT] [--debug]

The development server is flask's built-in WSGI server.  For anything beyond
local experimentation, deploy behind a production WSGI server (e.g. gunicorn
or waitress) using ``create_app`` from :mod:`app`.
"""

from __future__ import annotations

import argparse

from app.config import DEFAULT_HOST, DEFAULT_PORT
from app.main import create_app


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run the NetLite development server.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="interface to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port to bind")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug mode")
    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    app = create_app()
    # By default we bind to 127.0.0.1 only; expose via --host/--port with
    # the SSRF policy still enforced app-wide.
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()