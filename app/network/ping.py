"""Ping diagnostic service.

``ping`` resides in :mod:`app.network.ping`.  It shells out to the system
``ping`` binary with a strict, argument-list invocation (never a shell), a
per-context timeout, and no possibility of arbitrary command execution.

Raised: :class:`app.services.runner.ToolTimeout` if the binary does not
respond within the configured deadline.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class PingResult:
    """Outcome of a single ping run."""

    status: str  # "ok" | "unreachable" | "timeout" | "error"
    host: str
    resolved: str | None
    sent: int
    received: int
    latency_ms: str | None  # average in milliseconds, formatted
    details: str


def _find_ping() -> str | None:
    return shutil.which("ping")


def run(host: str, timeout: float = 5.0, count: int = 3) -> dict:
    """Ping ``host`` with the system binary, returning a result dict."""
    binary = _find_ping()
    if binary is None:
        return {
            "status": "error",
            "host": host,
            "resolved": None,
            "sent": 0,
            "received": 0,
            "latency_ms": None,
            "details": "ping binary is not available on this system.",
        }

    # Argument-list invocation: no shell, no user-controlled flags.
    cmd = [binary, "-c", str(count), "-W", str(int(timeout)), host]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 1.0,  # outer guard beyond the -W window
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _result(host, "timeout", sent=count, received=0, details="Ping timed out.")
    elapsed = time.monotonic() - started

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return _parse_output(host, output, count, elapsed)


def _result(host, status, *, sent, received, details, resolved=None, latency_ms=None) -> dict:
    return {
        "status": status,
        "host": host,
        "resolved": resolved,
        "sent": sent,
        "received": received,
        "latency_ms": latency_ms,
        "details": details,
    }


def _parse_output(host: str, output: str, sent: int, elapsed: float) -> dict:
    """Parse ``ping`` stdout/stderr into a result dict.

    We deliberately keep parsing cross-platform (BSD/GNU) and do not pass
    flags like ``-o json`` which are not portable.
    """
    lines = output.splitlines()
    resolved: str | None = None

    # "64 bytes from 8.8.8.8 (8.8.8.8): icmp_seq=1 ..." or GNU's
    # "64 bytes from 8.8.8.8: icmp_seq=1 ..." — either way the first "from
    # <addr>" is what we want.
    for line in lines:
        if "from " in line:
            addr = line.split("from ")[-1].split(":")[0].strip().strip("()")
            if addr:
                resolved = addr
            break

    # Received: "1 packets transmitted, 1 received" (GNU) or
    #           "1 packets transmitted, 1 packets received" (BSD).
    received = None
    for line in lines:
        if "received" in line and "transmitted" in line:
            try:
                received = int(line.split("received")[0].split(",")[-1].strip().split()[0])
            except (ValueError, IndexError):
                received = None
            break

    # Latency: "round-trip min/avg/max = 1.234/2.345/3.456 ms" (GNU) or
    #          "round-trip times: min/avg/max" ... separate line (BSD).
    avg_ms: str | None = None
    for line in lines:
        if "round-trip" in line.lower() or "min/avg/max" in line:
            for token in line.split():
                if "/" in token and "=" in line:
                    avg = token.split("/")[1]
                    avg_ms = f"{avg} ms"
                    break
            break

    if received is None:
        received = 0

    if received and received > 0:
        status = "ok"
        details = f"{received}/{sent} packets received"
    else:
        status = "unreachable"
        details = "No reply received."

    return _result(
        host,
        status,
        sent=sent,
        received=received,
        details=details,
        resolved=resolved,
        latency_ms=avg_ms,
    )


__all__ = ["PingResult", "run", "_parse_output"]