"""Runtime orchestration for guarded model execution."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

from app import settings
from app.guards import EgressGuard, GuardArm, GuardDecision, IngressGuard

ModelCallable = Callable[[Dict[str, Any]], Awaitable[Any]]
ClarifyHandler = Callable[[Dict[str, Any], GuardDecision], Awaitable["GuardResponse"]]


@dataclass
class GuardResponse:
    status_code: int
    body: Any
    headers: Dict[str, str]


def _allow_decision() -> GuardDecision:
    return {
        "action": "allow",
        "mode": "normal",
        "incident_id": "",
        "reason": "ok",
        "details": {},
    }


class GuardedRouter:
    """Coordinates ingress/egress guards around a model invocation."""

    def __init__(
        self,
        ingress_guard: GuardArm,
        egress_guard: GuardArm,
        *,
        clarify_handler: Optional[ClarifyHandler] = None,
    ) -> None:
        self._ingress_guard = ingress_guard
        self._egress_guard = egress_guard
        self._clarify_handler = clarify_handler
        self._ingress_enabled = settings.GUARD_INGRESS_ENABLED
        self._egress_enabled = settings.GUARD_EGRESS_ENABLED

    async def route(
        self,
        *,
        tenant: str,
        modality: str,
        request_id: str,
        payload: Any,
        model: ModelCallable,
    ) -> GuardResponse:
        ctx: Dict[str, Any] = {
            "tenant": tenant,
            "modality": modality,
            "request_id": request_id,
            "payload": payload,
        }

        ingress_decision = await self._evaluate_guard(
            guard=self._ingress_guard,
            ctx=ctx,
            enabled=self._ingress_enabled,
            fallback_action="block",
            fallback_mode="block_input_only",
            fallback_reason="ingress_guard_error",
        )

        if ingress_decision["action"] == "block":
            body = {
                "error": ingress_decision.get("reason", "blocked"),
                "incident_id": ingress_decision.get("incident_id", ""),
            }
            return self._build_response(422, body, ingress_decision, _allow_decision())

        if ingress_decision["action"] == "clarify":
            if self._clarify_handler:
                return await self._clarify_handler(ctx, ingress_decision)
            incident = ingress_decision.get("incident_id") or str(uuid.uuid4())
            body = {"error": "clarification_required", "incident_id": incident}
            return self._build_response(409, body, ingress_decision, _allow_decision())

        try:
            model_output = await model(ctx)
        except Exception as exc:  # pragma: no cover - surface model failures
            incident = ingress_decision.get("incident_id") or str(uuid.uuid4())
            body = {
                "error": "model_execution_failed",
                "incident_id": incident,
                "details": str(exc),
            }
            egress_decision = _allow_decision()
            egress_decision.update({"action": "clarify", "mode": "execute_locked"})
            egress_decision["incident_id"] = incident
            egress_decision["reason"] = "model_error"
            return self._build_response(500, body, ingress_decision, egress_decision)

        ctx["model_output"] = model_output

        egress_decision = await self._evaluate_guard(
            guard=self._egress_guard,
            ctx=ctx,
            enabled=self._egress_enabled,
            fallback_action="clarify",
            fallback_mode="execute_locked",
            fallback_reason="egress_guard_error",
        )

        if egress_decision["action"] == "block":
            incident_block: Optional[str] = (
                ingress_decision.get("incident_id") or egress_decision.get("incident_id")
            )
            body = {
                "error": egress_decision.get("reason", "blocked"),
                "incident_id": incident_block or "",
            }
            return self._build_response(503, body, ingress_decision, egress_decision)

        if egress_decision["action"] == "clarify":
            incident_clarify: Optional[str] = (
                ingress_decision.get("incident_id") or egress_decision.get("incident_id")
            )
            body = {
                "error": "output_locked",
                "incident_id": incident_clarify or "",
            }
            return self._build_response(409, body, ingress_decision, egress_decision)

        final_body = ctx.get("model_output")
        return self._build_response(200, final_body, ingress_decision, egress_decision)

    async def _evaluate_guard(
        self,
        *,
        guard: GuardArm,
        ctx: Dict[str, Any],
        enabled: bool,
        fallback_action: str,
        fallback_mode: str,
        fallback_reason: str,
    ) -> GuardDecision:
        if not enabled:
            return _allow_decision()
        try:
            return await guard.evaluate(ctx)
        except Exception as exc:
            incident = str(uuid.uuid4())
            return {
                "action": fallback_action,
                "mode": fallback_mode,
                "incident_id": incident,
                "reason": fallback_reason,
                "details": {"error": str(exc)},
            }

    def _build_response(
        self,
        status_code: int,
        body: Any,
        ingress_decision: GuardDecision,
        egress_decision: GuardDecision,
    ) -> GuardResponse:
        headers = {
            "X-Guardrail-Decision-Ingress": ingress_decision["action"],
            "X-Guardrail-Mode-Ingress": ingress_decision["mode"],
            "X-Guardrail-Decision-Egress": egress_decision["action"],
            "X-Guardrail-Mode-Egress": egress_decision["mode"],
        }
        incident = ingress_decision.get("incident_id") or egress_decision.get("incident_id")
        if incident:
            headers["X-Guardrail-Incident-ID"] = incident
        return GuardResponse(status_code=status_code, body=body, headers=headers)


_default_router: GuardedRouter | None = None


def get_default_router() -> GuardedRouter:
    global _default_router
    if _default_router is None:
        _default_router = GuardedRouter(IngressGuard(), EgressGuard())
    return _default_router


__all__ = ["GuardResponse", "GuardedRouter", "get_default_router"]
