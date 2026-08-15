# NetLite Security Model

This document is the authoritative description of NetLite's security model.
Treat any deviation from these controls as a regression and add a test for it
(see `tests/test_security.py`, `tests/test_ssrf.py`).

---

## 1. Threat model

NetLite is a **loopback-bound, stateless local utility with no
authentication**. The intended deployment is:

```
Browser  ──HTMX/forms──►  NetLite  (127.0.0.1:5000)  ──►  network services
   │                         │
   └── same host ────────────┘
```

Because there are no sessions and no cookies, the strongest practical CSRF
defense is a **stateless same-origin check** on state-changing requests
(`app/main.py::_csrf_check`): any POST carrying an `Origin` header that does
not match the request's own scheme+host+port is rejected with `403 HTTP`. Plain
curl/pytest clients (no `Origin`) are treated as non-browser and pass, which
matches the local-tool intent.

> If you expose NetLite beyond loopback, put a real authentication proxy in
> front and keep `NETLITE_ALLOW_PRIVATE=0`. There is intentionally **no
> built-in auth**.

---

## 2. SSRF (Server-Side Request Forgery) policy

The HTTP inspector fetches URLs on the server's behalf. This is the highest
severity attack surface, so it has the most defense-in-depth.

### 2.1 What is blocked

By default (`NETLITE_ALLOW_PRIVATE=0`) the following destinations are never
contacted:

| Class | Examples |
| --- | --- |
| Loopback | `127.0.0.0/8`, `::1` |
| Private RFC1918 | `10/8`, `172.16/12`, `192.168/16` |
| Link-local / CGNAT | `169.254/16`, `100.64/10` |
| "This network" / broadcast | `0.0.0.0/8`, `255.255.255.255/32` |
| Multicast / reserved | `224/4`, `240/4` |
| IPv6 special-purpose | `::`, `fc00::/7`, `fe80::/10`, `2001:db8::/32` |
| IPv4-mapped IPv6 | `::ffff:0:0/96` (re-checked) |

**Always blocked even with the opt-in flag:**

- Cloud metadata endpoints: `169.254.169.254/32`
- `0.0.0.0/8`, `255.255.255.255/32`, `::1/128`

### 2.2 How the check is applied

1. **URL normalization** (`app/validation.py::parse_url`) restricts schemes to
   `http`/`https`, rejects embedded credentials and fragments, IDNA-normalizes
   the hostname, and rejects malformed ports.
2. **Pre-connect check** — the hostname is resolved and *every* address is
   validated (`app/network/ssrf.py::check_hostname`). Any blocked address
   aborts the request before a socket is opened.
3. **Pinned connection** — the validated connection classes
   (`app/network/http.py::_ValidatedHTTPConnection/HTTPSConnection`) perform
   their **own** resolution through the same guard and connect to the
   SSRF-allowed address, while sending the original hostname in the `Host`
   header / TLS SNI. This closes the DNS-rebinding TOCTOU: the address the
   check approved is exactly the address that gets connected to.
4. **Per-redirect re-check** — every `Location` hop is re-parsed and
   re-validated (`_SsrfRedirectHandler`), so a public URL that 302s to a
   private range is still blocked. Redirects are capped at 5.

### 2.3 The `NETLITE_ALLOW_PRIVATE=1` opt-in

Switching this on permits loopback/private/link-local/CGNAT targets. It is
**strongly discouraged** and exists only for niche local-only use (e.g.
probing a LAN router's admin page). Even with it enabled, the *always-blocked*
table in §2.1 remains enforced.

### 2.4 Notes on other tools

`ping`, `dns`, and `tcp` intentionally do **not** apply the SSRF policy: they
are *local diagnostics* that may legitimately probe private ranges, and
NetLite is bound to loopback so only the local user can invoke them. If you
change the bind address, this behavior becomes a private-network scanner for
remote visitors — do not do that without adding policy gating to those tools.

---

## 3. Command execution safety

- **Ping** is the only subprocess. It invokes the system binary with an
  argument list and **no shell** (`subprocess.run([binary, "-c", n, "-W", t,
  host], ...)`). The host passes strict validation upstream, and count/timeout
  are int/float typed. No user input ever becomes a shell token.
- There is **no** generic "run command", "execute", or "eval" endpoint,
  and no `shell=True` anywhere in the codebase.

---

## 4. Input validation

All user input is validated in `app/validation.py` and again defensively per
tool:

- **Hostname**: optional trailing dot stripped, IDNA-encoded, must match a
  conservative RFC 1035 regex, ≤ 253 chars, labels ≤ 63 chars, control
  characters rejected. IP literals are canonicalized via `ipaddress`.
- **Port**: strict decimal `1-65535` (`[1-9][0-9]{0,4}` fullmatch); signed,
  hex, zero, padded, or whitespace-wrapped strings are rejected.
- **URL**: `http(s)` only; embedded credentials and fragments rejected;
  hostname re-validated; port re-validated.
- **Form fields**: trimmed and length-capped (`512` chars) at the route layer;
  the HTTP request body is capped at 1 MiB (`MAX_CONTENT_LENGTH`).

---

## 5. Network timeouts and resource bounds

Every external operation has a finite deadline:

| Operation | Timeout |
| --- | --- |
| TCP connect | `NETLITE_CONNECT_TIMEOUT` (default 5 s), per attempt |
| DNS resolution | bounded by the runner's outer fence |
| HTTP connect / read | `NETLITE_CONNECT_TIMEOUT` / `NETLITE_READ_TIMEOUT` |
| Ping | `NETLITE_PING_TIMEOUT` per packet + outer subprocess timeout |
| Any tool call | global backstop in the runner: `connect + read + 2 s` |

Additional bounds:

- HTTP response body is read at most `NETLITE_MAX_RESPONSE_BYTES` (256 KiB).
- Redirects capped at 5.
- Worker pool capped at 8 threads (daemon), so a pathological peer can
  exhaust its own worker but never block the process.
- `run.py`'s Flask dev server is for development; use a production WSGI
  server with proper worker limits when deploying.

---

## 6. Errors, leakage, and storage hygiene

- Tool services return canned messages; raw `strerror`/errno text never
  reaches the response (DNS/TCP map `gai`/socket errors to friendly text).
- `_run_and_render` catches unexpected errors and renders a generic message;
  the real traceback goes only to the server log.
- The global error handlers return generic HTML/JSON (no stack traces).
- History stores only: tool, target, status, timestamp, and a short summary —
  never request bodies, headers, or raw responses.
- SQLite queries are parameterized; stored fields are length-truncated
  (target 255, summary 500).

---

## 7. Output encoding / XSS

- All templates use Jinja autoescape; user-controlled values are inserted
  only through `{{ }}`, never `|safe` or `Markup`.
- Active content is served only from `app/static/vendor` (vendored,
  pinned HTMX + Alpine builds); no inline scripts, no remote scripts.
- CSP: `default-src 'self'; script-src 'self' 'unsafe-eval'; style-src
  'self' 'unsafe-inline'; ...`. The `'unsafe-eval'` exception is required by
  Alpine.js's expression evaluator; inline/remote scripts (the main XSS
  vector) remain blocked.
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, private `Cache-Control`.

---

## 8. Test coverage of the security surface

`tests/test_security.py` and `tests/test_ssrf.py` assert:

- cross-origin POST → 403; same-origin / no-Origin → allowed;
- loopback/private/link-local/always-blocked addresses rejected;
- IPv4-mapped IPv6 and IPv6 loopback blocked;
- the validated connection pins the resolved (allowed) address — DNS-rebinding
  window closed (`test_dns_rebinding_race_closed`);
- strict port rejection table (signs, hex, whitespace, 0, 65536);
- no raw OS error leakage in DNS/TCP messages;
- `NETLITE_MAX_HISTORY` is capped at `MAX_HISTORY_LIMIT`;
- timeout mapping and generic-error behavior at the route layer.

Run them with:

```console
$ .venv/bin/python -m pytest tests/test_security.py tests/test_ssrf.py -v
```

---

## 9. Exposing beyond loopback — checklist

1. Add real authentication (reverse proxy or app-level token).
2. Keep `NETLITE_ALLOW_PRIVATE=0`.
3. Use a production WSGI server (gunicorn/waitress) + HTTPS.
4. Add rate limiting (`/tools/*` currently rely on the 8-worker pool only).
5. Re-run the full test suite and this audit's cases against the new
   deployment.