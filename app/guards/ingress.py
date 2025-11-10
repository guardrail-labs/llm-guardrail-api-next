# app/guards/ingress.py
"""Ingress guard implementation with sanitizer integration."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, cast, Dict

from app.sanitizer import sanitize_input

Decision = Dict[str, Any]
Context = Dict[str, Any]
PolicyRunner = Callable[[Context], Awaitable[Decision] | Decision]


class IngressGuard:
    """Apply sanitization and delegate to a policy runner."""

    def __init__(self, *, policy_runner: PolicyRunner | None = None) -> None:
        self._policy_runner: PolicyRunner = policy_runner or self._default_policy

    async def run(self, ctx: Context) -> tuple[Decision, Context]:
        payload = ctx.get("payload", "")
        raw_text = self._extract_text(payload)

        sanitized = sanitize_input(raw_text)
        ctx["payload_raw"] = raw_text

        normalized = self._normalize_payload(payload, sanitized)
        ctx["payload_normalized"] = normalized

        self._update_payload(ctx, normalized)

        # ---- execute policy without type: ignore ----
        res = self._policy_runner(ctx)
        if inspect.isawaitable(res):
            decision = await cast(Awaitable[Decision], res)
        else:
            decision = cast(Decision, res)
        # ---------------------------------------------

        if decision.get("action", "allow") == "allow":
            normalized_after = ctx.get("payload_normalized")
            if normalized_after is not None and (
                isinstance(payload, MutableMapping)
                == isinstance(normalized_after, MutableMapping)
            ):
                ctx["payload"] = normalized_after

        return decision, ctx

    @staticmethod
    def skipped() -> Decision:
        return {"action": "skipped"}

    @staticmethod
    def _extract_text(payload: Any) -> str:
        if isinstance(payload, MutableMapping):
            if "text" in payload:
                value = payload.get("text")
                return value if isinstance(value, str) else str(value)
        if isinstance(payload, str):
            return payload
        return str(payload)

    @staticmethod
    def _normalize_payload(payload: Any, sanitized: str) -> Any:
        if isinstance(payload, MutableMapping):
            normalized_payload: dict[str, Any] = dict(payload)
            if "text" in normalized_payload:
                normalized_payload["text"] = sanitized
            return normalized_payload
        return sanitized

    @staticmethod
    def _update_payload(ctx: Context, normalized: Any) -> None:
        ctx["payload"] = normalized

    @staticmethod
    def _default_policy(ctx: Context) -> Decision:
        return {"action": "allow", "payload": ctx.get("payload")}
