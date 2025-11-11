from __future__ import annotations

import importlib
from typing import Callable

from fastapi import FastAPI, Request


# Best-effort lookup to reflect live arm mode; fall back to "normal" if unavailable.
def _current_mode() -> str:
    try:
        mod = importlib.import_module("app.runtime.arm")  # type: ignore[import-not-found]
        # Prefer a simple string accessor if present.
        if hasattr(mod, "current_mode_str"):
            return getattr(mod, "current_mode_str")()  # type: ignore[misc]
        # Fallbacks: common alt names
        if hasattr(mod, "get_current_mode_str"):
            return getattr(mod, "get_current_mode_str")()  # type: ignore[misc]
        if hasattr(mod, "get_arm_mode"):
            return str(getattr(mod, "get_arm_mode")())  # type: ignore[misc]
    except Exception:
        # Swallow import/runtime issues and default to "normal"
        pass
    return "normal"


def install_mode_header(app: FastAPI) -> None:
    """
    Install an OUTERMOST function-style middleware that unconditionally sets
    X-Guardrail-Mode on every response (2xx/4xx/5xx). Must be registered
    before any other middleware to guarantee header presence even on 404/422.
    """

    @app.middleware("http")
    async def _mode_header(request: Request, call_next: Callable):
        mode = _current_mode()
        response = await call_next(request)
        # Ensure exactly one header; set if missing.
        if "X-Guardrail-Mode" not in response.headers:
            response.headers["X-Guardrail-Mode"] = mode
        return response
