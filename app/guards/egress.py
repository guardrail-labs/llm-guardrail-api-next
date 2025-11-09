"""Egress guard implementation."""

from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from app.guards.ingress import _map_policy_action
from app.sanitizers.unicode_sanitizer import sanitize_text

Context = MutableMapping[str, Any]
Decision = Dict[str, Any]


class EgressGuard:
    """Apply policy enforcement for outbound payloads."""

    async def run(self, ctx: Context) -> tuple[Decision, Context]:
        decision: Decision = {
            "details": {},
            "action": "allow",
            "mode": "allow",
            "reason": "policy_allow",
        }

        policy_result = self._evaluate_policy(ctx)
        ctx.setdefault("policy", {})["egress_result"] = dict(policy_result)

        transformed = policy_result.get("sanitized_text")
        if transformed:
            decision["details"]["sanitized_text"] = transformed
            payload = ctx.get("model_response")
            if isinstance(payload, MutableMapping):
                for key in ("text", "message", "prompt", "content"):
                    if key in payload and isinstance(payload[key], str):
                        payload[key] = transformed
                        break
                ctx["model_response"] = payload
            elif isinstance(payload, str):
                ctx["model_response"] = transformed

            ctx.setdefault("policy", {})["egress_applied_sanitization"] = True

        action = policy_result.get("action", "allow")
        decision["action"], decision["mode"], decision["reason"] = _map_policy_action(action)
        decision["incident_id"] = policy_result.get("incident_id")
        decision["policy_result"] = dict(policy_result)
        return decision, ctx

    def skipped(self) -> Decision:
        decision: Decision = {
            "details": {},
            "action": "skipped",
            "mode": "skipped",
            "reason": "skipped",
        }
        return decision

    def _evaluate_policy(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        payload = ctx.get("model_response")
        text: str | None = None
        if isinstance(payload, str):
            text = payload
        elif isinstance(payload, Mapping):
            for key in ("text", "message", "prompt", "content"):
                val = payload.get(key)
                if isinstance(val, str):
                    text = val
                    break
        if text is None:
            return {"action": "allow"}

        sanitized, stats = sanitize_text(text)
        return {"action": "allow", "sanitized_text": sanitized, "stats": stats}


__all__ = ["EgressGuard"]
