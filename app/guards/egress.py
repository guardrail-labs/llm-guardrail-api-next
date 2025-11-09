"""Simplified egress guard implementation."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Iterable

Decision = Dict[str, Any]
Context = Dict[str, Any]


class EgressGuard:
    """Minimal egress guard wrapper for policy execution."""

    def __init__(
        self,
        *,
        processors: Iterable[Callable[[Context], Awaitable[Decision] | Decision]] | None = None,
    ) -> None:
        self._processors = list(processors or [])

    async def run(self, ctx: Context) -> tuple[Decision, Context]:
        decision: Decision = {"action": "allow"}
        for processor in self._processors:
            result = processor(ctx)
            if isinstance(result, dict):
                decision = result
            else:
                decision = await result
            if decision.get("action") in {"deny", "block"}:
                break
        return decision, ctx

    @staticmethod
    def skipped() -> Decision:
        return {"action": "skipped"}
