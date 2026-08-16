"""Dispatch a tool request to its network service.

Execution and validation rules live in the tool registry
(:mod:`app.tools`); this module only adds the outer timeout fence.
"""

from __future__ import annotations

from ..config import Config
from ..tools import TOOLS
from ..validation import ValidationError
from .runner import run_with_timeout


def run_tool(slug: str, *, target: str, config: Config, extra: dict | None = None) -> dict:
    """Validate and execute one tool with a bounded wall-clock deadline.

    Validation raises synchronously (the runner only propagates thread
    exceptions); the network call itself runs inside
    :func:`run_with_timeout` with the tool's configured budget, so no
    request can block the worker indefinitely.
    """
    tool = TOOLS.get(slug)
    if tool is None:
        raise ValidationError(f"Unknown tool: {slug!r}")

    # Validate inputs *before* submitting work.
    params = tool.validate(target, extra or {})

    return run_with_timeout(lambda: tool.run(params, config), tool.budget(config))


__all__ = ["run_tool"]
