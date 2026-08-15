"""HTTP inspector service.

Fetches a URL **from the server's network position** and reports response
metadata (status, timing, headers, redirect chain) without downloading
arbitrary content.

Constraints enforced here:

* only ``http``/``https`` (validated by :mod:`app.validation`);
* bounded connect + read timeouts;
* response body truncated to ``max_response_bytes``;
* redirect handling with a hard cap (no infinite loops);
* SSRF guard -- never contacts private/loopback/link-local targets unless
  ``NETLITE_ALLOW_PRIVATE=1`` is set (see :mod:`app.network.ssrf`).
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from ..config import Config
from ..validation import ParsedURL, parse_url
from . import ssrf

#: Hard cap on redirects followed per request (defense against loops/abuse).
MAX_REDIRECTS = 5

#: User-Agent we present; honest and identifiable.
USER_AGENT = "NetLite/0.1 (+local diagnostics)"


class HttpResponseTooLarge(Exception):
    """Raised when the response body exceeds the configured cap."""


def inspect(raw_url: str, config: Config) -> dict:
    """Inspect ``raw_url`` and return a metadata dict.

    Every network call is bounded; failures are surfaced as result states
    rather than exceptions so the UI can render them nicely.
    """
    parsed = parse_url(raw_url)
    _assert_scheme(parsed)

    # SSRF policy check happens BEFORE any socket is opened.
    decision = ssrf.check_hostname(parsed.hostname, allow_private=config.allow_private)
    if not decision.allowed:
        return {
            "url": parsed.target,
            "final_url": None,
            "status_code": None,
            "elapsed_ms": 0.0,
            "content_type": None,
            "server": None,
            "content_length": None,
            "redirects": 0,
            "error": decision.reason,
        }

    result: dict = {
        "url": parsed.target,
        "final_url": None,
        "status_code": None,
        "elapsed_ms": 0.0,
        "content_type": None,
        "server": None,
        "content_length": None,
        "redirects": 0,
        "error": None,
    }

    start = time.monotonic()
    body = b""
    try:
        req = urllib.request.Request(
            parsed.target,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        with urllib.request.urlopen(
            req, timeout=config.connect_timeout, context=_ssl_context()
        ) as resp:
            result["status_code"] = resp.status
            result["final_url"] = resp.geturl()
            result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)

            ctype = resp.headers.get("Content-Type")
            if ctype:
                result["content_type"] = ctype.split(";")[0].strip()
            server = resp.headers.get("Server")
            if server:
                result["server"] = server.strip()[:120]
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit():
                result["content_length"] = int(clen)

            # Consume only up to the cap so memory stays flat.
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                body += chunk
                if len(body) > config.max_response_bytes:
                    result["error"] = (
                        f"Response body exceeded the {config.max_response_bytes} byte "
                        "limit; content was truncated."
                    )
                    break
    except HttpResponseTooLarge:
        result["error"] = "Response body too large; download aborted."
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None) or exc
        result["error"] = _friendly_error(reason)
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)

    return result


def _assert_scheme(parsed: ParsedURL) -> None:
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")


def _ssl_context():
    import ssl

    ctx = ssl.create_default_context()
    return ctx


def _friendly_error(exc) -> str:
    """Convert a urllib/HTTP error into a short, user-friendly message."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP error {exc.code} {exc.reason}."
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, TimeoutError):
            return "The request timed out."
        if isinstance(reason, ssl.SSLError):
            return f"TLS error: {reason}"
        if isinstance(reason, OSError):
            return f"Connection failed: {reason}"
        return f"Could not fetch URL: {reason}"
    if isinstance(exc, TimeoutError):
        return "The request timed out."
    return f"Request failed: {exc}"


__all__ = ["inspect", "HttpResponseTooLarge"]