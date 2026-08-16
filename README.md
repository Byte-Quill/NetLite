# NetLite

**Lightweight, self-hostable network diagnostics toolkit.** A small Flask web
application that provides common network troubleshooting tools through a clean
server-rendered browser interface.

```
NetLite
  ├── Ping            reachability + latency via the system ping binary
  ├── DNS Lookup      IPv4 / IPv6 / canonical hostname resolution
  ├── Port Check      single TCP port open/closed/timeout check
  ├── HTTP Inspector  response metadata (status, headers, timing, redirects)
  └── Local Network   hostname, addresses, gateway, DNS of this machine
```

Designed around five principles:

1. **Extremely low resource usage** — no build step, no worker processes,
   SQLite only, minimal JS (HTMX + Alpine.js, vendored locally).
2. **Fast startup** — one Flask app, one executor pool, no warm-up work.
3. **Minimal dependencies** — Flask + requests are the only runtime dependencies.
4. **Security** — input validation, SSRF protection, bounded timeouts, CSRF
   same-origin check, secure headers. See [Security model](#security-model) and
   [docs/security.md](docs/security.md).
5. **Progressive enhancement** — server-rendered HTML fragments swapped by
   HTMX; the interface works even without JavaScript enabled (form posts
   still render results).

---

## Quick Start

Requires **Python 3.12+**.

```console
$ python3 run.py
```

That's it. On first run the script creates a `.venv`, installs the single
dependency (Flask), and relaunches itself inside it — no manual venv or pip
steps needed. Then open <http://127.0.0.1:5000/>.

> By default NetLite binds to `127.0.0.1` only. You can override with
> `--host` / `--port`, but **do not expose it to the internet** without
> reading [docs/security.md](docs/security.md) — the tools probe networks by
> design and there is intentionally no authentication layer.

---

## Features

| Tool            | Input            | Output                                                        |
| --------------- | ---------------- | ------------------------------------------------------------ |
| **Ping**        | hostname / IP    | resolved address, reachability, latency, packets sent/received |
| **DNS Lookup**  | hostname         | IPv4 addresses, IPv6 addresses, canonical name               |
| **Port Check**  | host + port      | open / closed / timeout / invalid, resolved addresses        |
| **HTTP Inspector** | http(s) URL   | status code, final URL, response time, content type, server header, content length, redirect count |
| **Local Network**  | —             | hostname, primary hostname, aliases, local IPv4/IPv6, IPv6 support, default gateway, DNS servers |

History is stored in SQLite (last **100** runs by default, configurable) with an
automatic retention cleanup. A short, non-sensitive summary is kept per run;
no request bodies, payloads, or headers are stored.

---

## Architecture

```
Browser
   │
   ├── HTMX        (server interaction, partial page swaps)
   └── Alpine.js   (local UI state: tool panel toggling)
          │
          ▼
       Flask
          │
    ┌─────┼──────────────┐
    ▼     ▼              ▼
 Network  SQLite    Templates
 Services            (Jinja2, server-rendered)
    │
    ├── Ping        (system binary via subprocess, arg-list only)
    ├── DNS         (socket.getaddrinfo / getnameinfo)
    ├── TCP         (socket.connect_ex, single host+port)
    ├── HTTP        (requests with SSRF-pinned connection adapter)
    └── Local Net   (socket + /proc/net/route + /etc/resolv.conf)
```

```
netlite/
├── app/
│   ├── __init__.py
│   ├── main.py            app factory (thin wiring point)
│   ├── config.py          env-driven immutable configuration
│   ├── extensions.py      typed accessors for app-level values
│   ├── middleware.py      secure headers, CSRF check, error handlers
│   ├── tools.py           declarative registry of diagnostic tools
│   ├── validation.py      hostname / IP / port / URL validators
│   ├── db.py              SQLite history persistence
│   ├── routes/            main (pages, history, health) + tools (POST endpoints)
│   ├── services/          dispatch + bounded runner (thread pool + timeouts)
│   ├── network/           ping, dns, tcp, http, netinfo, ssrf
│   ├── templates/         Jinja2 base + dashboard + history + tool partials
│   └── static/            css/style.css + vendor/ (htmx, alpine — local)
├── tests/                 pytest suite (no external network required)
├── instance/              runtime data (SQLite) — gitignored
├── docs/security.md       security model and SSRF policy
├── run.py                 development entry point
├── pyproject.toml         pytest + ruff + coverage config
├── requirements.txt       Flask + requests (runtime deps)
├── LICENSE                MIT
└── README.md
```

### Request lifecycle

1. Browser POSTs a tool form; HTMX targets `#result`.
2. The route reads and length-limits the form fields declared by the tool's
   registry entry (`app/tools.py`).
3. `app/services/dispatch.run_tool` validates the input (strict host / port /
   URL rules from the registry), then executes the network service **inside a
   bounded worker thread** with a hard wall-clock deadline.
4. The service returns a plain dict; the route renders an HTML fragment with
   Jinja autoescaping and records a non-sensitive history row (summary format
   also comes from the registry).
5. HTMX swaps the fragment into the page.

Every external network operation carries an explicit timeout (connect, read,
ping, and an outer backstop) so a slow peer can never block a request forever.

---

## Development

```console
$ .venv/bin/python -m pytest            # run tests
$ .venv/bin/python -m pytest --cov=app  # coverage report
$ .venv/bin/python -m ruff check .      # lint
```

The test suite does **not** require internet access: network services are
mocked (see `tests/test_ping.py`, `tests/test_http.py`, `tests/test_tcp.py`,
`tests/test_dns.py`) and the app factory uses an ephemeral temp database
(`tests/conftest.py`).

To run a live smoke test:

```console
$ .venv/bin/python run.py &
$ curl -s http://127.0.0.1:5000/api/health
{"app":"netlite","status":"ok","version":"0.1.0"}
```

### Contributing / workflow

- One logical change per commit, conventional messages
  (`feat:`, `fix:`, `test:`, `docs:`, `security:`, `chore:`).
- Run `pytest` and `ruff` before committing.
- Do not add a dependency unless the standard library cannot reasonably do it.

---

## Configuration

All settings come from `NETLITE_*` environment variables (see
`app/config.py` for the complete list and validation).

| Variable                       | Default               | Notes                                       |
| ------------------------------ | --------------------- | ------------------------------------------- |
| `NETLITE_HOST` / `NETLITE_PORT` | `127.0.0.1` / `5000`  | bind address (keep loopback!)               |
| `NETLITE_SECRET_KEY`            | `dev-only-change-me`  | change in any non-local deployment          |
| `NETLITE_DB`                    | `netlite.sqlite3`     | SQLite file, resolved under `instance/`     |
| `NETLITE_MAX_HISTORY`           | `100`                 | retention cap (max `5000`)                  |
| `NETLITE_MAX_CONTENT_LENGTH`    | `1048576` (1 MiB)     | request body limit                          |
| `NETLITE_CONNECT_TIMEOUT`       | `5.0`                 | seconds                                     |
| `NETLITE_READ_TIMEOUT`          | `10.0`                | seconds                                     |
| `NETLITE_PING_TIMEOUT`          | `5.0`                 | seconds per ping packet                     |
| `NETLITE_MAX_RESPONSE_BYTES`    | `262144` (256 KiB)    | HTTP inspector body cap                     |
| `NETLITE_ALLOW_PRIVATE`         | `0`                   | **do not enable casually** — see SSRF policy |

---

## Security Model

NetLite is a **loopback-bound local utility with no authentication**, by
design. Its threat model assumes the browser and server run on the same host.

Applied controls:

- **Input validation** — strict hostname/IP/port/URL rules in `app/validation.py`
  (IDNA, RFC 1035 shape, `1-65535` ports, `http(s)`-only schemes).
- **SSRF protection** — the HTTP inspector refuses private/loopback/link-local/
  reserved targets by default and re-checks **every redirect hop**; connection
  classes pin the SSRF-validated resolved address (DNS-rebinding safe). See
  [docs/security.md](docs/security.md).
- **Bounded network operations** — every tool runs inside a worker with a
  wall-clock deadline; sockets carry connect/read timeouts.
- **CSRF** — stateless same-origin check on all POSTs (no cookies exist).
- **No arbitrary command execution** — ping uses an argument-list subprocess
  with a validated host; there is no shell, no `shell=True`, and no generic
  "run command" endpoint anywhere.
- **Output escaping** — Jinja autoescape on all templates; no `|safe`.
- **Secure headers** — CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, private caching.
- **No information leakage** — error handlers and tool services return canned
  messages; raw OS/socket errors are never sent to the client.
- **SQLite parameterization** — all queries are parameterized.

### Hardening before exposing beyond loopback

1. Put it behind a real auth proxy (or add a token).
2. Keep `NETLITE_ALLOW_PRIVATE=0`.
3. Consider a production WSGI server (gunicorn/waitress) and HTTPS.
4. Review rate limiting: the only current guard is the 8-worker executor pool.

---

## License

MIT — see [LICENSE](LICENSE).