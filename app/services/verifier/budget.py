from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


class VerifierTimedOut(TimeoutError):
    """Raised when a verifier call exceeds the configured latency budget."""


async def within_budget(coro_factory: Callable[[], Awaitable[T]], *, budget_ms: Optional[int]) -> T:
    """Run the given coroutine factory within an optional latency budget.

    If ``budget_ms`` is ``None`` the coroutine runs without a timeout. If the
    coroutine exceeds the budget, :class:`VerifierTimedOut` is raised.
    """
    if budget_ms is None:
        return await coro_factory()

    timeout_s = max(0.0, budget_ms / 1000.0)
    try:
        return await asyncio.wait_for(coro_factory(), timeout=timeout_s)
    except asyncio.TimeoutError as exc:  # pragma: no cover - sanity
        raise VerifierTimedOut(f"Verifier exceeded budget: {budget_ms} ms") from exc
