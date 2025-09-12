# app/services/verifier/router_adapter.py
# Summary (PR-D update):
# - Adds probabilistic sampling using an injectable RNG (default: random.random).
# - Continues enforcing latency budgets via within_budget().
# - Keeps external API behavior stable; timeouts return allowed=True with a reason.
# - Fully typed and ruff-compliant (≤100 columns).

from __future__ import annotations

import random
from typing import Callable, Optional, Protocol

from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_sampling_pct,
)
from app.services.verifier.budget import within_budget, VerifierTimedOut
from app.services.verifier.result_types import VerifierOutcome


class _Provider(Protocol):
    """Typed interface expected from providers."""

    async def evaluate(self, text: str) -> VerifierOutcome:
        ...


class VerifierAdapter:
    """Apply fractional sampling and latency budget around a provider.

    Sampling is probabilistic: a random draw in [0, 1) must be < sampling_pct to
    invoke the provider; otherwise the verifier is skipped.
    """

    def __init__(
        self,
        provider: _Provider,
        *,
        rng: Optional[Callable[[], float]] = None,
    ) -> None:
        self._provider = provider
        # Injectable RNG for deterministic tests
        self._rng: Callable[[], float] = rng if rng is not None else random.random

    @property
    def sampling_pct(self) -> float:
        return get_verifier_sampling_pct()

    @property
    def budget_ms(self) -> Optional[int]:
        return get_verifier_latency_budget_ms()

    async def evaluate(self, text: str) -> VerifierOutcome:
        sp = self.sampling_pct
        if sp <= 0.0:
            return VerifierOutcome(allowed=True, reason="sampling=0.0 (skipped)")

        # Probabilistic gate: only call provider when draw < sampling_pct
        draw = self._rng()
        if not (0.0 <= draw < sp):
            return VerifierOutcome(
                allowed=True,
                reason=f"sampling=skip p={sp:.3f} r={draw:.3f}",
            )

        async def _call() -> VerifierOutcome:
            return await self._provider.evaluate(text)

        try:
            return await within_budget(_call, budget_ms=self.budget_ms)
        except VerifierTimedOut:
            return VerifierOutcome(
                allowed=True, reason="verifier_timeout_budget_exceeded"
            )
