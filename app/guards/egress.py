"""Egress guard implementation."""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, Optional

from app import settings
from app.egress.redaction import redact_response_body

from .base import GuardDecision

_DEFAULT_REASON = "ok"


def _default_decision() -> GuardDecision:
    return {
        "action": "allow",
        "mode": "normal",
        "incident_id": "",
        "reason": _DEFAULT_REASON,
        "details": {},
    }


class EgressGuard:
    """Guard that post-processes model output before returning to the caller."""

    def __init__(
        self,
        *,
        redactor: Optional[Callable[[bytes, str | None], bytes]] = None,
    ) -> None:
        self._enabled = settings.GUARD_EGRESS_ENABLED
        self._redactor = redactor or redact_response_body

    async def evaluate(self, ctx: Dict[str, Any]) -> GuardDecision:
        if not self._enabled:
            return _default_decision()
        try:
            return await self._evaluate(ctx)
        except Exception as exc:  # pragma: no cover - defensive
            incident = str(uuid.uuid4())
            decision = _default_decision()
            decision.update(
                {
                    "action": "clarify",
                    "mode": "execute_locked",
                    "incident_id": incident,
                    "reason": "egress_guard_error",
                    "details": {"error": str(exc)},
                }
            )
            return decision

    async def _evaluate(self, ctx: Dict[str, Any]) -> GuardDecision:
        decision = _default_decision()
        model_output = ctx.get("model_output")
        if model_output is None:
            decision["reason"] = "no_output"
            return decision

        transformed = _redact_output(model_output, self._redactor)
        if transformed is not None:
            ctx["model_output"] = transformed
            decision["details"] = {"transformed": True}
        else:
            decision["details"] = {"transformed": False}
        return decision


def _redact_output(output: Any, redactor: Callable[[bytes, str | None], bytes]) -> Any | None:
    if isinstance(output, bytes):
        redacted = redactor(output, "application/octet-stream")
        return redacted if redacted != output else None
    if isinstance(output, str):
        encoded = output.encode("utf-8")
        redacted = redactor(encoded, "text/plain")
        decoded = redacted.decode("utf-8")
        return decoded if decoded != output else None
    if isinstance(output, dict):
        text = json.dumps(output, ensure_ascii=False).encode("utf-8")
        redacted = redactor(text, "application/json")
        try:
            decoded_obj: Any = json.loads(redacted.decode("utf-8"))
        except json.JSONDecodeError:
            decoded_obj = output
        return decoded_obj if decoded_obj != output else None
    if isinstance(output, list):
        changed: bool = False
        new_items = []
        for item in output:
            transformed = _redact_output(item, redactor)
            if transformed is not None:
                changed = True
                new_items.append(transformed)
            else:
                new_items.append(item)
        return new_items if changed else None
    return None


__all__ = ["EgressGuard"]
