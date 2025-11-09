"""Ingress guard implementation."""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Optional

from app import settings
from app.sanitizer import detect_confusables, sanitize_input
from app.services.policy import apply_policies

from .base import GuardDecision, GuardException

_DEFAULT_REASON = "ok"


def _default_decision() -> GuardDecision:
    return {
        "action": "allow",
        "mode": "normal",
        "incident_id": "",
        "reason": _DEFAULT_REASON,
        "details": {},
    }


class IngressGuard:
    """Apply sanitization and policy evaluation before model execution."""

    def __init__(
        self,
        *,
        sanitizer_enabled: Optional[bool] = None,
        policy_evaluator: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self._sanitizer_enabled = (
            settings.SANITIZER_ENABLED if sanitizer_enabled is None else sanitizer_enabled
        )
        self._policy_evaluator = policy_evaluator or apply_policies

    async def evaluate(self, ctx: Dict[str, Any]) -> GuardDecision:
        try:
            return await self._evaluate(ctx)
        except GuardException:
            raise
        except Exception as exc:  # pragma: no cover - safety net
            incident_id = str(uuid.uuid4())
            decision = _default_decision()
            decision.update(
                {
                    "action": "block",
                    "mode": "block_input_only",
                    "incident_id": incident_id,
                    "reason": "ingress_guard_error",
                    "details": {"error": str(exc)},
                }
            )
            return decision

    async def _evaluate(self, ctx: Dict[str, Any]) -> GuardDecision:
        decision = _default_decision()
        payload = ctx.get("payload")
        sanitizer_info: Dict[str, Any] = {"enabled": self._sanitizer_enabled, "confusables": []}

        if self._sanitizer_enabled and payload is not None:
            sanitized_payload = sanitize_input(payload)
            ctx["payload"] = sanitized_payload
            sanitizer_info["confusables"] = _collect_confusables(sanitized_payload)
        ctx["sanitizer"] = sanitizer_info

        text_sample = _extract_text(ctx.get("payload"))
        if text_sample is None:
            decision["reason"] = "no_text"
            return decision

        policy_result = self._policy_evaluator(text_sample)
        decision["details"] = {
            "risk_score": policy_result.get("risk_score", 0),
            "hits": policy_result.get("hits", []),
        }
        transformed = policy_result.get("sanitized_text")
        if transformed:
            decision["details"]["sanitized_text"] = transformed
            ctx.setdefault("policy", {})["sanitized_text"] = transformed

        action = policy_result.get("action", "allow")
        decision["action"], decision["mode"], decision["reason"] = _map_policy_action(action)
        if decision["action"] == "block":
            decision.setdefault("details", {})["hits"] = policy_result.get("hits", [])
        return decision


def _extract_text(payload: Any) -> Optional[str]:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        for key in ("text", "prompt", "input", "message"):
            value = payload.get(key)
            if isinstance(value, str):
                return value
    return None


def _collect_confusables(payload: Any) -> list[str]:
    if isinstance(payload, str):
        return detect_confusables(payload)
    if isinstance(payload, dict):
        findings: list[str] = []
        for value in payload.values():
            findings.extend(_collect_confusables(value))
        return list(dict.fromkeys(findings))
    if isinstance(payload, (list, tuple, set)):
        findings_list: list[str] = []
        for item in payload:
            findings_list.extend(_collect_confusables(item))
        return list(dict.fromkeys(findings_list))
    return []


def _map_policy_action(action: str) -> tuple[str, str, str]:
    if action == "deny":
        return "block", "block_input_only", "policy_deny"
    if action == "clarify":
        return "clarify", "normal", "policy_clarify"
    if action == "sanitize":
        return "allow", "normal", "policy_sanitize"
    return "allow", "normal", _DEFAULT_REASON


__all__ = ["IngressGuard"]
