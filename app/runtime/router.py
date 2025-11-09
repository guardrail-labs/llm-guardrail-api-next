"""Runtime router orchestrating ingress/model/egress arms."""

from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.guards.egress import EgressGuard
from app.guards.ingress import IngressGuard

Context = MutableMapping[str, Any]
Decision = Dict[str, Any]

router = APIRouter()

_INGRESS_GUARD = IngressGuard()
_EGRESS_GUARD = EgressGuard()


def _merge_incident_ids(ing_id: str | None, eg_id: str | None) -> str | None:
    return ing_id or eg_id


async def _call_model(ctx: Context) -> Mapping[str, Any]:
    payload = ctx.get("payload")
    if isinstance(payload, MutableMapping):
        return dict(payload)
    if isinstance(payload, Mapping):
        return dict(payload)
    if isinstance(payload, str):
        return {"text": payload}
    return {"text": ""}


def _decision_headers(ingress: Decision, egress: Decision) -> Dict[str, str]:
    headers = {
        "X-Guardrail-Decision-Ingress": str(ingress.get("action", "allow")),
        "X-Guardrail-Mode-Ingress": str(ingress.get("mode", "allow")),
        "X-Guardrail-Decision-Egress": str(egress.get("action", "allow")),
        "X-Guardrail-Mode-Egress": str(egress.get("mode", "allow")),
    }
    incident = _merge_incident_ids(ingress.get("incident_id"), egress.get("incident_id"))
    if incident:
        headers["X-Guardrail-Incident-ID"] = incident
    return headers


@router.post("/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    payload = await request.json()
    ctx: Context = {
        "payload": payload,
        "headers": dict(request.headers),
        "modality": (payload.get("modality") if isinstance(payload, Mapping) else None) or "text",
    }

    ingress_decision, ctx = await _INGRESS_GUARD.run(ctx)
    ctx.setdefault("decisions", {})["ingress"] = ingress_decision

    if ingress_decision.get("action") in {"deny", "block", "lock"}:
        egress_decision = _EGRESS_GUARD.skipped()
        headers = _decision_headers(ingress_decision, egress_decision)
        return JSONResponse({"error": "blocked"}, status_code=400, headers=headers)

    if ingress_decision.get("action") == "clarify":
        egress_decision = _EGRESS_GUARD.skipped()
        headers = _decision_headers(ingress_decision, egress_decision)
        return JSONResponse({"clarify": True}, status_code=202, headers=headers)

    model_response = await _call_model(ctx)
    ctx["model_response"] = model_response

    try:
        egress_decision, ctx = await _EGRESS_GUARD.run(ctx)
    except Exception as exc:
        egress_decision = {
            "details": {"error": str(exc)},
            "action": "error",
            "mode": "error",
            "reason": "egress_exception",
            "incident_id": None,
        }
        headers = _decision_headers(ingress_decision, egress_decision)
        return JSONResponse({"error": "egress_failed"}, status_code=500, headers=headers)
    ctx["decisions"]["egress"] = egress_decision

    headers = _decision_headers(ingress_decision, egress_decision)
    return JSONResponse(model_response, headers=headers)


__all__ = [
    "router",
    "chat_completions",
    "_merge_incident_ids",
    "_call_model",
]
