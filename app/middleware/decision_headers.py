from __future__ import annotations

from typing import Any, Mapping, Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

try:
    from app.runtime.arm import get_arm_runtime as _get_arm_runtime
except Exception:  # pragma: no cover - guard against optional runtime packages
    _get_arm_runtime = None

_DECISION_KEY_CANDIDATES = ("guardrail_decision", "decision")


def _extract_decision(attrs: Any) -> Optional[Mapping[str, Any]]:
    if attrs is None:
        return None
    for key in _DECISION_KEY_CANDIDATES:
        value = getattr(attrs, key, None) if hasattr(attrs, key) else None
        if isinstance(value, dict):
            return value
    return None


def _coerce_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    stringified = str(value).strip()
    return stringified or None


_DEFAULT_MODE_HEADER = "normal"


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

    return _coerce_str(header_value)


def _current_arm_mode_header() -> str:
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


class DecisionHeaderMiddleware(BaseHTTPMiddleware):
    """Add headers that surface guardrail decision metadata if present."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        fallback_mode = _current_arm_mode_header()

        response = await call_next(request)
        decision = _extract_decision(getattr(request, "state", None))

        outcome: Optional[str] = None
        mode: Optional[str] = None
        incident_id: Optional[str] = None

        if decision:
            outcome = _coerce_str(decision.get("outcome") or decision.get("decision"))
            mode = _coerce_str(decision.get("mode"))
            incident_id = _coerce_str(
                decision.get("incident_id")
                or decision.get("incident")
                or decision.get("request_id")
            )

        if not mode:
            mode = fallback_mode

        try:
            if outcome:
                from app.observability import metrics_decisions as _md

                _md.inc(
                    outcome,
                    tenant=getattr(request.state, "tenant", None),
                    bot=getattr(request.state, "bot", None),
                )
        except Exception:
            pass

        if outcome and "X-Guardrail-Decision" not in response.headers:
            response.headers["X-Guardrail-Decision"] = outcome
        if "X-Guardrail-Mode" not in response.headers and mode:
            response.headers["X-Guardrail-Mode"] = mode
        if incident_id and "X-Guardrail-Incident-ID" not in response.headers:
            response.headers["X-Guardrail-Incident-ID"] = incident_id
        return response
