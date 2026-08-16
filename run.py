"""Development entry point for NetLite.

Usage:
    python3 run.py [--host HOST] [--port PORT] [--debug]

That's it.  On first run this script creates a ``.venv`` next to itself,
installs the (single) dependency, and relaunches inside it -- so you never
need to create or activate a virtual environment by hand.

The development server is Flask's built-in WSGI server.  For anything beyond
local experimentation, deploy behind a production WSGI server (e.g. gunicorn
or waitress) using ``create_app`` from :mod:`app`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
_VENV_DIR = _PROJECT_ROOT / ".venv"
_VENV_PYTHON = _VENV_DIR / ("Scripts" if os.name == "nt" else "bin") / "python"


def _create_venv() -> None:
    """Create ``.venv``; tolerate systems without ensurepip (Debian/Ubuntu)."""
    import importlib.util
    import venv

    print(f"[setup] Creating virtual environment in {_VENV_DIR} ...")
    # Ubuntu's python3 without python3-venv lacks ensurepip and the venv
    # module sys.exit()s in that case -- detect it up front instead.
    with_pip = importlib.util.find_spec("ensurepip") is not None
    venv.EnvBuilder(with_pip=with_pip, clear=False).create(_VENV_DIR)


def _ensure_pip() -> None:
    """Make sure pip exists in the current interpreter, bootstrapping if not."""
    probe = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True)
    if probe.returncode == 0:
        return
    print("[setup] Bootstrapping pip ...")
    import tempfile
    import urllib.request

    get_pip = Path(tempfile.gettempdir()) / "netlite-get-pip.py"
    try:
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", get_pip)
        subprocess.check_call([sys.executable, str(get_pip), "--quiet"])
    except Exception as exc:
        raise SystemExit(
            f"Could not bootstrap pip ({exc}).\n"
            "On Debian/Ubuntu install it once with:  sudo apt install python3-venv\n"
            "then re-run:  python3 run.py"
        ) from exc
    finally:
        get_pip.unlink(missing_ok=True)


def _bootstrap() -> None:
    """Make sure Flask is importable, creating a venv + installing if needed.

    Returns silently when dependencies are already available.  Otherwise this
    creates ``.venv``, installs ``requirements.txt`` into it, and re-executes
    this script with the venv's Python so the rest of the program runs there.
    """
    try:
        import flask  # noqa: F401

        return  # dependencies present; nothing to do
    except ImportError:
        pass

    if not _VENV_PYTHON.exists():
        _create_venv()

    # If we are not yet running inside that venv, relaunch with its Python.
    # (Compare sys.prefix, not executable paths: the venv's python is a
    # symlink to the system interpreter, so resolved paths look identical.)
    if Path(sys.prefix).resolve() != _VENV_DIR.resolve():
        os.execv(str(_VENV_PYTHON), [str(_VENV_PYTHON), __file__, *sys.argv[1:]])

    # We are inside the venv but Flask is missing: install dependencies once.
    if os.environ.get("_NETLITE_BOOTSTRAPPED"):
        raise SystemExit(
            "Dependency setup failed. Try manually: "
            f"{_VENV_PYTHON} -m pip install -r {_PROJECT_ROOT / 'requirements.txt'}"
        )
    os.environ["_NETLITE_BOOTSTRAPPED"] = "1"

    _ensure_pip()
    print("[setup] Installing dependencies ...")
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "-r",
            str(_PROJECT_ROOT / "requirements.txt"),
        ]
    )
    # Relaunch so the freshly installed packages are importable.
    os.execv(sys.executable, [sys.executable, __file__, *sys.argv[1:]])


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    from app import __version__
    from app.config import DEFAULT_HOST, DEFAULT_PORT

    parser = argparse.ArgumentParser(description="Run the NetLite development server.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="interface to bind")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port to bind")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug mode")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    _bootstrap()

    from app.main import create_app

    args = parse_args(argv)
    app = create_app()
    # By default we bind to 127.0.0.1 only; expose via --host/--port with
    # the SSRF policy still enforced app-wide.
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
