"""Cross-cutting HTTP concerns: secure headers, CSRF defense, error pages.

Kept separate from the app factory so :mod:`app.main` stays a thin
composition point and each concern can evolve independently.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, abort, current_app, jsonify, request


def _same_origin(a: str, b: str) -> bool:
    """Return True when two URLs share scheme+host+port.

    Comparison is normalized (case-insensitive scheme/netloc, trailing slash
    stripped) so equivalent origins compare equal regardless of how the
    browser serialized them.
    """
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
    # Never cache diagnostic results; small and efficient for a local utility.
    response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
    return response


def _csrf_check() -> None:
    """Stateless CSRF defense: require same-origin on state-changing requests.

    NetLite keeps no sessions, so there is no cookie to pair with a token.
    Instead we enforce the strongest stateless check available: POSTs whose
    ``Origin`` does not match this host are rejected.  A malicious website
    cannot forge this header (browsers block cross-origin sends of ``Origin``)
    and cross-site form posts carry a foreign Origin that is rejected.  Only
    live browser requests carry an Origin header, so non-browser clients
    (curl, pytest) are unaffected.
    """
    if request.method != "POST":
        return
    if request.origin is None:
        return  # non-browser clients have no Origin header
    expected = request.scheme + "://" + request.host
    if not _same_origin(request.origin, expected):
        current_app.logger.warning("CSRF check blocked cross-origin POST from %s", request.origin)
        abort(403)


def register_error_handlers(app: Flask) -> None:
    """Register JSON responses for API routes, friendly HTML elsewhere."""

    def _api_or_plain(status: int, error: str, message: str | None = None):
        if request.path.startswith("/api/"):
            payload = {"error": error}
            if message:
                payload["message"] = message
            return jsonify(payload), status
        return error, status

    @app.errorhandler(400)
    def bad_request(err):
        return _api_or_plain(400, "Bad request", str(err) or "Invalid input")

    @app.errorhandler(404)
    def not_found(err):
        return _api_or_plain(404, "Not found", "Unknown API endpoint")

    @app.errorhandler(405)
    def method_not_allowed(err):
        return _api_or_plain(405, "Method not allowed")

    @app.errorhandler(413)
    def too_large(err):
        return _api_or_plain(413, "Payload too large")

    @app.errorhandler(500)
    def internal_error(err):
        # Never leak tracebacks to clients.
        app.logger.error("Unhandled error: %s", err)
        return _api_or_plain(500, "Internal server error")
