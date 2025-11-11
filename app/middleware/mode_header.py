from __future__ import annotations

from typing import Callable

from fastapi import FastAPI, Request

from app.runtime.arm import current_guardrail_mode


def _current_mode() -> str:
    """Return the live guardrail mode string; default to "normal" on error."""

    try:
        mode = current_guardrail_mode()
        if isinstance(mode, str):
            return mode
        value = getattr(mode, "value", None)
        if isinstance(value, str):
            return value
        return str(mode)
    except Exception:
        return "normal"


def install_mode_header(app: FastAPI) -> None:
    """
    Install an OUTERMOST middleware that ensures X-Guardrail-Mode is emitted on
    every response, including error paths.
    """

    @app.middleware("http")
    async def _mode_header(request: Request, call_next: Callable):
        mode = _current_mode()
        response = await call_next(request)
        if "X-Guardrail-Mode" not in response.headers:
            response.headers["X-Guardrail-Mode"] = mode
        return response
