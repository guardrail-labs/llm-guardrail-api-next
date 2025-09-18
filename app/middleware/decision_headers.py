from __future__ import annotations

from typing import Any, Mapping, Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

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


class DecisionHeaderMiddleware(BaseHTTPMiddleware):
    """Add headers that surface guardrail decision metadata if present."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        decision = _extract_decision(getattr(request, "state", None))
        if not decision:
            return response

        outcome = _coerce_str(decision.get("outcome") or decision.get("decision"))
        mode = _coerce_str(decision.get("mode"))
        incident_id = _coerce_str(
            decision.get("incident_id")
            or decision.get("incident")
            or decision.get("request_id")
        )

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
        if mode and "X-Guardrail-Mode" not in response.headers:
            response.headers["X-Guardrail-Mode"] = mode
        if incident_id and "X-Guardrail-Incident-ID" not in response.headers:
            response.headers["X-Guardrail-Incident-ID"] = incident_id
        return response
