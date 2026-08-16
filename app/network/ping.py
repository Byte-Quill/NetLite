"""Ping diagnostic service — cross-platform (Windows / macOS / Linux).

Invokes the system ``ping`` binary via an explicit argument list -- never a
shell -- with strict hostname validation upstream.  The binary is looked up
once per call with :func:`shutil.which`; a missing binary degrades gracefully
to a friendly error result instead of raising.

All network machinery is bounded:

* ``-W <seconds>`` (Linux/macOS) / ``-w <milliseconds>`` (Windows) bounds the
  per-packet wait inside the binary;
* the subprocess call itself has an outer timeout covering the worst case
  (``count`` packets, 1s apart, each waiting up to ``timeout``), so a
  wedged ping process cannot hang the worker forever.

The output parser handles GNU (Linux), BSD (macOS/FreeBSD), and Windows
``ping`` output formats with simple, conservative pattern matching.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

# GNU: "min/avg/max = 12.3/14.5/16.2 ms"
# BSD: "min/avg/max/stddev = 12.3/14.5/16.2/0.9 ms"
_LATENCY_RE = re.compile(r"\=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/[\d.]+)?\s*ms")

# Windows: "Minimum = 12ms, Maximum = 16ms, Average = 14ms"
_WIN_LATENCY_RE = re.compile(r"Average\s*=\s*([\d.]+)\s*ms")

# "3 packets transmitted, 3 received, 0% packet loss"        (GNU)
# "3 packets transmitted, 3 packets received, 0.0% packet loss" (BSD)
_TRANSMITTED_RE = re.compile(r"(\d+)\s+packets? transmitted,\s+(\d+)\s+(?:packets?\s+)?received")

# Windows: "    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),"
# Windows: "    Packets: Sent = 3, Received = 3, Lost = 3 (100% loss),"
_WIN_RECEIVED_RE = re.compile(r"Received\s*=\s*(\d+)")

_IS_WINDOWS = os.name == "nt"


def estimate_duration(timeout: float, count: int = 3) -> float:
    """Worst-case wall-clock time for a ping run (packets 1s apart)."""
    return count * (timeout + 1.0) + 2.0


def _build_command(binary: str, host: str, timeout: float, count: int) -> list[str]:
    """Build the ping argument list for this platform (no shell involved)."""
    if os.name == "nt":
        # Windows: -n count, -w per-packet timeout in milliseconds.
        return [binary, "-n", str(count), "-w", str(int(max(timeout, 1)) * 1000), host]
    # macOS/BSD ping also supports -c/-W; GNU uses -c/-W as well.
    return [binary, "-c", str(count), "-W", str(int(max(timeout, 1))), host]


def run(host: str, timeout: float = 5.0, count: int = 3) -> dict:
    """Ping ``host`` with the system binary, returning a result dict."""
    binary = shutil.which("ping")
    if binary is None:
        return _result(
            host,
            "error",
            sent=0,
            received=0,
            details="ping binary is not available on this system.",
        )

    # Argument-list invocation: no shell, no user-controlled flags.
    cmd = _build_command(binary, host, timeout, count)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            # Windows ping may emit OEM-codepage text; never crash on decode.
            errors="replace",
            timeout=estimate_duration(timeout, count),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _result(
            host,
            "timeout",
            sent=count,
            received=0,
            details=f"Ping did not finish within {timeout}s.",
        )

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return _parse_output(host, output, count)


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


def _parse_output(host: str, output: str, sent: int) -> dict:
    """Parse GNU/BSD/Windows ping stdout+stderr into a result dict."""
    lines = output.splitlines()

    resolved: str | None = None
    for line in lines:
        if "from " in line:
            addr = line.split("from ")[-1].split(":")[0].strip().strip("()")
            if addr:
                resolved = addr
            break

    received: int | None = None
    for line in lines:
        match = _TRANSMITTED_RE.search(line)
        if match:
            received = int(match.group(2))
            break
    if received is None:
        for line in lines:
            match = _WIN_RECEIVED_RE.search(line)
            if match:
                received = int(match.group(1))
                break

    avg_ms: str | None = None
    for line in lines:
        match = _LATENCY_RE.search(line)
        if match:
            avg_ms = f"{match.group(2)} ms"
            break
    if avg_ms is None:
        for line in lines:
            match = _WIN_LATENCY_RE.search(line)
            if match:
                avg_ms = f"{match.group(1)} ms"
                break

    if received is None:
        received = 0

    # Surface a more specific message for common failure modes.
    if received and received > 0:
        status = "ok"
        details = f"{received}/{sent} packets received"
    elif "name resolution" in output.lower() or "not known" in output.lower():
        status = "error"
        details = "Could not resolve the target hostname."
    elif "could not find host" in output.lower() or "unable to resolve" in output.lower():
        status = "error"
        details = "Could not resolve the target hostname."
    elif "no route" in output.lower() or "network is unreachable" in output.lower():
        status = "unreachable"
        details = "Destination network is unreachable."
    elif "destination host unreachable" in output.lower():
        status = "unreachable"
        details = "Destination host is unreachable."
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


__all__ = ["_build_command", "_parse_output", "estimate_duration", "run"]
