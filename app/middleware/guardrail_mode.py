from __future__ import annotations

from typing import Any, Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

_DEFAULT_MODE_HEADER = "normal"

try:  # pragma: no cover - optional dependency during import
    from app.runtime.arm import get_arm_runtime as _get_arm_runtime
except Exception:  # pragma: no cover - runtime lookup failure should not break flow
    _get_arm_runtime = None


def _mode_header_from_arm(mode_obj: Any) -> Optional[str]:
    if mode_obj is None:
        return None

    header_value: Optional[str] = None
    try:
        header_value = getattr(mode_obj, "header_value", None)
        if callable(header_value):  # pragma: no cover - defensive
            header_value = header_value()
    except Exception:  # pragma: no cover - defensive
        header_value = None

    if not header_value:
        try:
            header_value = getattr(mode_obj, "value", None) or str(mode_obj)
        except Exception:  # pragma: no cover - defensive
            header_value = None

    if header_value is None:
        return None

    header_value = str(header_value).strip()
    return header_value or None


def current_guardrail_mode() -> str:
    if _get_arm_runtime is None:
        return _DEFAULT_MODE_HEADER

    try:
        runtime = _get_arm_runtime()
    except Exception:  # pragma: no cover - runtime lookup should not break flow
        return _DEFAULT_MODE_HEADER

    try:
        mode_obj = runtime.evaluate_mode()
    except Exception:  # pragma: no cover - runtime lookup should not break flow
        mode_obj = getattr(runtime, "mode", None)

    mode = _mode_header_from_arm(mode_obj)
    return mode or _DEFAULT_MODE_HEADER


class GuardrailModeMiddleware(BaseHTTPMiddleware):
    """Ensure every response surfaces the guardrail mode header."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        mode = current_guardrail_mode()
        if mode and "X-Guardrail-Mode" not in response.headers:
            response.headers["X-Guardrail-Mode"] = mode
        return response
