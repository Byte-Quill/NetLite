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


class SsrfBlockedError(Exception):
    """Raised internally when a (redirect) hop is blocked by SSRF policy."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _SsrfRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate EVERY redirect hop against the SSRF policy.

    urllib follows redirects transparently; without re-checking each hop a
    public URL that 302s to a private / loopback address would bypass the
    initial guard.  This handler ensures no redirect target ever touches a
    blocked range.
    """

    def __init__(self, allow_private: bool):
        super().__init__()
        self._allow_private = allow_private
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if self.count > MAX_REDIRECTS:
            raise SsrfBlockedError(f"Too many redirects (max {MAX_REDIRECTS}).")

        try:
            parsed = parse_url(newurl)
        except ValidationError as exc:
            raise SsrfBlockedError(f"Redirect target is invalid: {exc}") from None

        decision = ssrf.check_hostname(
            parsed.hostname, allow_private=self._allow_private
        )
        if not decision.allowed:
            raise SsrfBlockedError(decision.reason or "Redirect blocked by policy.")

        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
        return _result(
            parsed.target,
            error=decision.reason,
        )

    result = _result(parsed.target)
    start = time.monotonic()
    opener = _build_opener(config.allow_private)
    try:
        req = urllib.request.Request(
            parsed.target,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        with opener.open(req, timeout=config.connect_timeout) as resp:
            redirects = getattr(
                getattr(opener, "redirect_handler", None), "count", 0
            )
            result.update(
                status_code=resp.status,
                final_url=resp.geturl(),
                elapsed_ms=round((time.monotonic() - start) * 1000, 1),
                redirects=redirects,
            )
            ctype = resp.headers.get("Content-Type")
            if ctype:
                result["content_type"] = ctype.split(";")[0].strip()
            server = resp.headers.get("Server")
            if server:
                result["server"] = server.strip()[:120]
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit():
                result["content_length"] = int(clen)

            # Read (and discard) only up to the cap so memory stays flat; this
            # proves the "no unlimited download" property in code.
            consumed = 0
            while True:
                chunk = resp.read(min(64 * 1024, config.max_response_bytes - consumed))
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed >= config.max_response_bytes:
                    result["error"] = (
                        f"Response body exceeded the {config.max_response_bytes} "
                        "byte limit; content was truncated."
                    )
                    break
    except SsrfBlockedError as exc:
        result["error"] = exc.reason
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx response is still valid response metadata: record it.
        result["status_code"] = exc.code
        ctype = exc.headers.get("Content-Type") if exc.headers else None
        if ctype:
            result["content_type"] = ctype.split(";")[0].strip()
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error"] = f"HTTP error {exc.code} {exc.reason}."
    except HttpResponseTooLarge:
        result["error"] = "Response body too large; download aborted."
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None) or exc
        result["error"] = _friendly_error(reason)
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)

    return result


def _result(url: str, error: str | None = None) -> dict:
    return {
        "url": url,
        "final_url": None,
        "status_code": None,
        "elapsed_ms": 0.0,
        "content_type": None,
        "server": None,
        "content_length": None,
        "redirects": 0,
        "error": error,
    }


def _assert_scheme(parsed: ParsedURL) -> None:
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")


def _build_opener(allow_private: bool):
    """Build an opener with the SSRF redirect guard and default TLS config.

    The returned opener carries a ``redirect_handler`` attribute so callers
    can inspect how many redirects were followed.
    """
    redirect_handler = _SsrfRedirectHandler(allow_private)
    handlers: list = [redirect_handler]
    if http.client.HTTPSConnection is not None:
        # Only add TLS handling when ssl is available (always true here).
        import ssl

        ctx = ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    opener.redirect_handler = redirect_handler
    return opener


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