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
from ..validation import ParsedURL, ValidationError, parse_url
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


# --------------------------------------------------------------------------
# DNS-rebinding-safe connection classes
# --------------------------------------------------------------------------
#
# urllib resolves the hostname a second time when it opens the socket, so a
# resolver could answer the SSRF check with a public IP and the connect with a
# private one (classic TOCTOU).  To close this window we perform our own
# resolution through the SSRF-validated helper at connect time and pin the
# socket to an allowed address, while keeping the original hostname for the
# `Host:` header and TLS SNI (virtual hosts still work).


def _ssrf_safe_resolve(hostname: str, port: int, allow_private: bool):
    """Return the first SSRF-allowed ``(family, type, proto, sockaddr)``.

    Raises :class:`SsrfBlockedError` when resolution fails or every address
    is blocked by policy.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise SsrfBlockedError(f"Could not resolve {hostname}.") from None

    blocked: list[str] = []
    for family, socktype, proto, _canon, sockaddr in infos:
        if socktype != socket.SOCK_STREAM:
            continue
        ip = sockaddr[0].split("%")[0]
        decision = ssrf.check_ip(ip, allow_private=allow_private)
        if decision.allowed:
            return family, socktype, proto, sockaddr
        blocked.append(ip)

    raise SsrfBlockedError(
        "Every resolved address of "
        f"{hostname} is blocked by the SSRF policy: {', '.join(blocked) or 'none'}."
    )


class _ValidatedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that resolves its peer through the SSRF guard."""

    _allow_private = False
    _connect_timeout = 5.0
    _read_timeout = 10.0

    def connect(self):
        _family, _stype, _proto, sockaddr = _ssrf_safe_resolve(
            self.host, self.port, self._allow_private
        )
        # getaddrinfo returns (addr, port[, flowinfo, scopeid]); create_connection
        # wants a (host, port) pair (family is implied or passed explicitly).
        pair = sockaddr[:2]
        self.sock = socket.create_connection(pair, timeout=self._connect_timeout)
        self.sock.settimeout(self._read_timeout)


class _ValidatedHTTPSConnection(_ValidatedHTTPConnection, http.client.HTTPSConnection):
    """HTTPSConnection variant: validated TCP + TLS with SNI = hostname.

    MRO is _ValidatedHTTPSConnection → _ValidatedHTTPConnection →
    HTTPSConnection → HTTPConnection; we re-declare __init__ so the SSL
    ``context`` kwarg urllib passes is accepted and stored on ``self._context``
    (used by connect()).
    """

    def __init__(self, host, port=None, *, context=None, **kwargs):
        self._context = context or ssl._create_default_https_context()
        super().__init__(host, port, **kwargs)

    def connect(self):
        _ValidatedHTTPConnection.connect(self)
        if self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=server_hostname
        )


class _ValidatedHTTPHandler(urllib.request.HTTPHandler):
    http_class = _ValidatedHTTPConnection

    def http_open(self, req):
        return self.do_open(self.http_class, req)


class _ValidatedHTTPSHandler(urllib.request.HTTPSHandler):
    https_class = _ValidatedHTTPSConnection

    def https_open(self, req):
        return self.do_open(self.https_class, req)


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
    try:
        opener = _build_opener(config)
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
        # (Must precede URLError: HTTPError subclasses it.)
        result["status_code"] = exc.code
        ctype = exc.headers.get("Content-Type") if exc.headers else None
        if ctype:
            result["content_type"] = ctype.split(";")[0].strip()
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error"] = f"HTTP error {exc.code} {exc.reason}."
    except urllib.error.URLError as exc:
        # SsrfBlockedError raised during connection setup is wrapped by urllib
        # in a URLError; unwrap it to surface the real policy message.
        wrapped = exc.reason
        if isinstance(wrapped, SsrfBlockedError):
            result["error"] = wrapped.reason
        else:
            result["error"] = _friendly_error(wrapped)
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
    except HttpResponseTooLarge:
        result["error"] = "Response body too large; download aborted."
    except (http.client.HTTPException, TimeoutError, OSError) as exc:
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


def _build_opener(cfg: Config):
    """Build an opener with SSRF-safe connection + redirect handling.

    The resolved peer is pinned to an SSRF-allowed address (closing the
    DNS-rebinding TOCTOU), redirects are re-validated per hop, and the
    returned opener carries a ``redirect_handler`` attribute so callers can
    inspect how many hops were followed.
    """
    redirect_handler = _SsrfRedirectHandler(cfg.allow_private)

    import ssl

    ssl_ctx = ssl.create_default_context()

    handlers: list = [
        _ValidatedHTTPHandler(),
        redirect_handler,
    ]
    if http.client.HTTPSConnection is not None:
        https_handler = _ValidatedHTTPSHandler(context=ssl_ctx)
        handlers.insert(0, https_handler)

    # Propagate timeout + SSRF settings into the connection classes.
    for cls in (_ValidatedHTTPConnection, _ValidatedHTTPSConnection):
        cls._allow_private = cfg.allow_private
        cls._connect_timeout = cfg.connect_timeout
        cls._read_timeout = cfg.read_timeout

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


__all__ = ["HttpResponseTooLarge", "inspect"]
