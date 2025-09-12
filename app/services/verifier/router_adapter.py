from __future__ import annotations

from typing import Optional, Protocol

from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_sampling_pct,
)
from app.services.verifier.budget import VerifierTimedOut, within_budget
from app.services.verifier.result_types import VerifierOutcome


class _Provider(Protocol):
    async def evaluate(self, text: str) -> VerifierOutcome:
        ...


class VerifierAdapter:
    """Adapter that applies sampling and latency budget around a provider."""

    def __init__(self, provider: _Provider):
        self._provider = provider

    @property
    def sampling_pct(self) -> float:
        return get_verifier_sampling_pct()

    @property
    def budget_ms(self) -> Optional[int]:
        return get_verifier_latency_budget_ms()

    async def evaluate(self, text: str) -> VerifierOutcome:
        if self.sampling_pct <= 0.0:
            return VerifierOutcome(allowed=True, reason="sampling=0.0 (skipped)")

        async def _call() -> VerifierOutcome:
            return await self._provider.evaluate(text)

        try:
            return await within_budget(_call, budget_ms=self.budget_ms)
        except VerifierTimedOut:
            return VerifierOutcome(
                allowed=True, reason="verifier_timeout_budget_exceeded"
            )
