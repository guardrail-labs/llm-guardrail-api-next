# app/guards/ingress.py
"""Ingress guard implementation with sanitizer integration."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Dict, MutableMapping, Optional

from app.sanitizer import sanitize_input

Decision = Dict[str, Any]
Context = Dict[str, Any]

# Public type users may pass in; we normalize to async in __init__.
PolicyRunnerLike = Callable[[Context], Decision] | Callable[[Context], Awaitable[Decision]]

# Internal, fully-normalized type (always async).
PolicyRunner = Callable[[Context], Awaitable[Decision]]


class IngressGuard:
    """Apply sanitization and delegate to a policy runner."""

    def __init__(self, *, policy_runner: Optional[PolicyRunnerLike] = None) -> None:
        if policy_runner is None:
            self._policy_runner: PolicyRunner = self._default_policy
        else:
            # Normalize to an async runner so downstream code is simple and well-typed.
            if inspect.iscoroutinefunction(policy_runner):
                self._policy_runner = policy_runner  
            else:
                sync_runner = policy_runner

                async def _wrapped(ctx: Context) -> Decision:
                    return sync_runner(ctx)  

                self._policy_runner = _wrapped

    async def run(self, ctx: Context) -> tuple[Decision, Context]:
        payload = ctx.get("payload", "")
        raw_text = self._extract_text(payload)

        sanitized = sanitize_input(raw_text)
        ctx["payload_raw"] = raw_text

        normalized = self._normalize_payload(payload, sanitized)
        ctx["payload_normalized"] = normalized

        self._update_payload(ctx, normalized)

        decision = await self._execute_policy(ctx)

        if decision.get("action", "allow") == "allow":
            normalized_now = ctx.get("payload_normalized")
            if normalized_now is not None and (
                isinstance(payload, MutableMapping) == isinstance(normalized_now, MutableMapping)
            ):
                ctx["payload"] = normalized_now

        return decision, ctx

    @staticmethod
    def skipped() -> Decision:
        return {"action": "skipped"}

    @staticmethod
    def _extract_text(payload: Any) -> str:
        if isinstance(payload, MutableMapping):
            if "text" in payload:
                value = payload.get("text")
                if isinstance(value, str):
                    return value
                return str(value)
        if isinstance(payload, str):
            return payload
        return str(payload)

    @staticmethod
    def _normalize_payload(payload: Any, sanitized: str) -> Any:
        if isinstance(payload, MutableMapping):
            normalized_payload: Dict[str, Any] = dict(payload)
            if "text" in normalized_payload:
                normalized_payload["text"] = sanitized
            return normalized_payload
        return sanitized

    @staticmethod
    def _update_payload(ctx: Context, normalized: Any) -> None:
        ctx["payload"] = normalized

    async def _execute_policy(self, ctx: Context) -> Decision:
        # _policy_runner is always async (PolicyRunner), so just await it.
        return await self._policy_runner(ctx)

    @staticmethod
    async def _default_policy(ctx: Context) -> Decision:
        return {"action": "allow", "payload": ctx.get("payload")}
