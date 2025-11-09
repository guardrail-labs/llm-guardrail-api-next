from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from app.sanitizers.unicode_sanitizer import sanitize_text

Context = MutableMapping[str, Any]
Decision = Dict[str, Any]

_BLOCK_ACTIONS = {"deny", "block", "lock"}


def _extract_primary_text(ctx: Mapping[str, Any]) -> str | None:
    """Attempt to pull the primary text payload from ``ctx``."""
    payload = ctx.get("payload")
    modality = (ctx.get("modality") or "text").lower()

    if isinstance(payload, str):
        return payload

    if isinstance(payload, Mapping):
        if modality in {"text", "message", "prompt"}:
            for key in ("text", "message", "prompt"):
                val = payload.get(key)
                if isinstance(val, str):
                    return val
        for key in ("input", "content", "body"):
            val = payload.get(key)
            if isinstance(val, str):
                return val

    text = ctx.get("text")
    return text if isinstance(text, str) else None


def _map_policy_action(action: str) -> tuple[str, str, str]:
    normalized = (action or "allow").strip().lower()
    if normalized in _BLOCK_ACTIONS:
        return "deny", "block", "policy_deny"
    if normalized == "clarify":
        return "clarify", "clarify", "policy_clarify"
    return "allow", "allow", "policy_allow"


class IngressGuard:
    """Apply policy enforcement for inbound payloads."""

    async def run(self, ctx: Context, *, modality: str | None = None) -> tuple[Decision, Context]:
        if modality:
            ctx["modality"] = modality
        else:
            ctx.setdefault("modality", "text")

        decision: Decision = {
            "details": {},
            "action": "allow",
            "mode": "allow",
            "reason": "policy_allow",
        }

        policy_result = self._evaluate_policy(ctx)
        ctx.setdefault("policy", {})["result"] = dict(policy_result)

        transformed = policy_result.get("sanitized_text")
        if transformed:
            # Record telemetry/debug
            decision["details"]["sanitized_text"] = transformed
            policy_ctx = ctx.setdefault("policy", {})
            policy_ctx["sanitized_text"] = transformed

            # 🔒 Forward sanitized payload so the model never sees the original unsafe text.
            payload = ctx.get("payload")
            modality_name = (ctx.get("modality") or "text").lower()

            if isinstance(payload, MutableMapping):
                # Prefer explicit text keys first
                if "text" in payload and modality_name in {"text", "message", "prompt"}:
                    payload["text"] = transformed
                elif "message" in payload and modality_name == "text":
                    payload["message"] = transformed
                elif "prompt" in payload and modality_name == "text":
                    payload["prompt"] = transformed
                else:
                    # Fallback: common generic keys
                    for key in ("input", "content", "body"):
                        if key in payload and isinstance(payload[key], str):
                            payload[key] = transformed
                            break
                ctx["payload"] = payload
            elif isinstance(payload, str):
                ctx["payload"] = transformed
            else:
                # Router sometimes keeps raw text separately
                if isinstance(ctx.get("text"), str):
                    ctx["text"] = transformed

            policy_ctx["applied_sanitization"] = True

        action = policy_result.get("action", "allow")
        decision["action"], decision["mode"], decision["reason"] = _map_policy_action(action)
        decision["incident_id"] = policy_result.get("incident_id")
        decision["policy_result"] = dict(policy_result)
        return decision, ctx

    def _evaluate_policy(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        text = _extract_primary_text(ctx)
        if text is None:
            return {"action": "allow"}

        sanitized, stats = sanitize_text(text)
        remove_controls = {code: None for code in range(32) if chr(code) not in {"\n", "\r", "\t"}}
        control_filtered = sanitized.translate(remove_controls)
        if control_filtered != sanitized:
            stats = dict(stats)
            stats["control_chars_removed"] = stats.get("control_chars_removed", 0) + 1
        sanitized = control_filtered
        result: Dict[str, Any] = {
            "action": "allow",
            "sanitized_text": sanitized,
            "stats": stats,
        }
        return result


__all__ = ["IngressGuard", "_map_policy_action"]
