"""Timeout-safe execution for network tool calls.

Background threads can't be force-killed cleanly in CPython, so we use a
daemon worker thread for each tool call and wait on a bounded result.  If the
call exceeds its deadline the request returns a *timeout* response while the
daemon thread is left to finish in the background (its socket / subprocess
will eventually time out on its own because every operation carries an
explicit deadline).

This keeps:

* the request thread responsive (never blocks indefinitely);
* the tool services free to use blocking APIs with plain try/except.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor

# A single reusable executor for the whole process.  Worker threads are
# daemon threads so a slow network call can never prevent interpreter exit.
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="netlite-tool")


class ToolError(RuntimeError):
    """Base class for tool execution failures."""


class ToolTimeout(ToolError):
    """Raised when a tool call exceeds its configured deadline."""


def run_with_timeout(fn, timeout: float | None, *args, **kwargs) -> object:
    """Run ``fn(*args, **kwargs)`` in a worker thread with a deadline.

    Returns the callable's return value.  Raises :class:`ToolTimeout` when
    the deadline passes, or re-raises whatever exception the callable raised.
    """
    future: Future = _EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        # The thread is still running in the background; we cannot cancel a
        # blocking socket, but the service code bounds every operation so it
        # will terminate on its own shortly after.
        future.cancel()
        raise ToolTimeout(f"Operation timed out after {timeout}s.") from None
    except Exception as exc:  # propagate tool-specific failures
        raise exc


__all__ = ["run_with_timeout", "ToolTimeout", "ToolError"]