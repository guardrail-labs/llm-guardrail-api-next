"""Runtime chat router with isolated ingress and egress guards."""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app import settings as settings_module
from app.guards import Context, Decision, EgressGuard, IngressGuard
from app.runtime.arm import ArmMode, get_arm_runtime
from app.services import decisions_bus

logger = logging.getLogger(__name__)

router = APIRouter()

SETTINGS = settings_module

_ARM_FAILURES: Dict[str, int] = {"ingress": 0, "egress": 0}
_INGRESS_GUARD = IngressGuard()
_EGRESS_GUARD = EgressGuard()


def _emit_arm_failure(arm: str) -> None:
    payload = {"arm": arm, "count": _ARM_FAILURES[arm]}
    emitter = getattr(decisions_bus, "emit", None)
    try:
        if callable(emitter):
            emitter("arm_failure", payload)
            return
        publisher = getattr(decisions_bus, "publish", None)
        if callable(publisher):
            publisher({"event": "arm_failure", **payload})
    except Exception:  # pragma: no cover - telemetry failures must not break flow
        logger.exception("failed to emit arm_failure metric", extra=payload)


def _decision_headers(ingress: Decision, egress: Decision, *, mode: ArmMode) -> Dict[str, str]:
    return {
        "X-Guardrail-Decision-Ingress": str(ingress.get("action", "allow")),
        "X-Guardrail-Decision-Egress": str(egress.get("action", "allow")),
        "X-Guardrail-Arm-Failures-Ingress": str(_ARM_FAILURES["ingress"]),
        "X-Guardrail-Arm-Failures-Egress": str(_ARM_FAILURES["egress"]),
        "X-Guardrail-Mode": mode.header_value,
    }


async def _call_model(ctx: Context) -> Any:
    payload = ctx.get("payload")
    if isinstance(payload, dict):
        return payload
    return {"output": payload}


@router.post("/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    payload = await request.json()
    ctx: Context = {"payload": payload, "headers": dict(request.headers)}
    runtime = get_arm_runtime()
    mode = runtime.evaluate_mode()

    annotations = ctx.setdefault("audit_annotations", {})
    if isinstance(annotations, dict):
        annotations["arm_mode"] = mode.value
        reason = runtime.ingress_degradation_reason
        if reason:
            annotations["ingress_degradation_reason"] = reason

    if mode is ArmMode.EGRESS_ONLY or not runtime.ingress_enabled:
        reason = runtime.ingress_degradation_reason
        ingress_decision = {
            "action": "skipped",
            "mode": "egress-only" if mode is ArmMode.EGRESS_ONLY else "disabled",
        }
        if reason:
            ingress_decision["reason"] = reason
    else:
        try:
            ingress_decision, ctx = await _INGRESS_GUARD.run(ctx)
        except Exception as exc:  # pragma: no cover - defensive path
            _ARM_FAILURES["ingress"] += 1
            _emit_arm_failure("ingress")
            fail_open = getattr(SETTINGS, "INGRESS_FAIL_OPEN_STRICT", False)
            if not fail_open:
                egress_decision = _EGRESS_GUARD.skipped()
                headers = _decision_headers(
                    {"action": "error"}, egress_decision, mode=mode
                )
                return JSONResponse(
                    {"error": "ingress_failed"},
                    status_code=500,
                    headers=headers,
                )
            flags = ctx.setdefault("flags", {})
            if isinstance(flags, dict):
                flags["strict_egress"] = True
            ingress_decision = {
                "action": "allow",
                "mode": "fail-open",
                "reason": str(exc),
            }

    if ingress_decision.get("action") in {"deny", "block", "lock", "block_input_only"}:
        egress_decision = _EGRESS_GUARD.skipped()
        headers = _decision_headers(ingress_decision, egress_decision, mode=mode)
        return JSONResponse({"error": "blocked"}, status_code=400, headers=headers)

    model_response = await _call_model(ctx)
    ctx["model_response"] = model_response

    if runtime.egress_enabled:
        try:
            egress_decision, ctx = await _EGRESS_GUARD.run(ctx)
        except Exception:  # pragma: no cover - defensive path
            _ARM_FAILURES["egress"] += 1
            _emit_arm_failure("egress")
            headers = _decision_headers(
                ingress_decision, {"action": "error"}, mode=mode
            )
            return JSONResponse(
                {"error": "egress_failed"}, status_code=500, headers=headers
            )
    else:
        egress_decision = _EGRESS_GUARD.skipped()

    if egress_decision.get("action") in {"deny", "block", "lock"}:
        headers = _decision_headers(ingress_decision, egress_decision, mode=mode)
        return JSONResponse({"error": "blocked"}, status_code=400, headers=headers)

    headers = _decision_headers(ingress_decision, egress_decision, mode=mode)
    return JSONResponse(model_response, headers=headers)


__all__ = [
    "_ARM_FAILURES",
    "_decision_headers",
    "chat_completions",
    "router",
]
