# app/services/verifier/router_adapter.py
# Summary (PR-D+E):
# - Probabilistic sampling with injectable RNG (default: random.random).
# - Enforces latency budgets via within_budget().
# - Records Prometheus metrics (sampled/skip/timeout + duration histogram).
# - Keeps external API behavior stable; timeouts return allowed=True with a reason.

from __future__ import annotations

import random
import time
from typing import Callable, Optional, Protocol

from app.observability.metrics import VERIFIER_METRICS, VerifierMetrics
from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_sampling_pct,
)
from app.services.verifier.budget import VerifierTimedOut, within_budget
from app.services.verifier.result_types import VerifierOutcome


class _Provider(Protocol):
    """Typed interface expected from providers."""

    async def evaluate(self, text: str) -> VerifierOutcome:
        ...


def _derive_provider_name(provider: object) -> str:
    name = getattr(provider, "name", None) or provider.__class__.__name__
    return str(name).lower()


class VerifierAdapter:
    """Apply fractional sampling, latency budget, and metrics around a provider.

    Sampling is probabilistic: a random draw in [0, 1) must be < sampling_pct to
    invoke the provider; otherwise the verifier is skipped.
    """

    def __init__(
        self,
        provider: _Provider,
        *,
        rng: Optional[Callable[[], float]] = None,
        metrics: Optional[VerifierMetrics] = None,
        provider_name: Optional[str] = None,
    ) -> None:
        self._provider = provider
        self._rng: Callable[[], float] = rng if rng is not None else random.random
        self._metrics = metrics if metrics is not None else VERIFIER_METRICS
        self._prov_name = provider_name or _derive_provider_name(provider)

    @property
    def sampling_pct(self) -> float:
        return get_verifier_sampling_pct()

    @property
    def budget_ms(self) -> Optional[int]:
        return get_verifier_latency_budget_ms()

    async def evaluate(self, text: str) -> VerifierOutcome:
        sp = self.sampling_pct
        if sp <= 0.0:
            self._metrics.skipped_total.labels(provider=self._prov_name).inc()
            return VerifierOutcome(allowed=True, reason="sampling=0.0 (skipped)")

        # Probabilistic gate: only call provider when draw < sampling_pct
        draw = self._rng()
        if not (0.0 <= draw < sp):
            self._metrics.skipped_total.labels(provider=self._prov_name).inc()
            return VerifierOutcome(
                allowed=True,
                reason=f"sampling=skip p={sp:.3f} r={draw:.3f}",
            )

        self._metrics.sampled_total.labels(provider=self._prov_name).inc()

        async def _call() -> VerifierOutcome:
            return await self._provider.evaluate(text)

        start = time.perf_counter()
        try:
            out = await within_budget(_call, budget_ms=self.budget_ms)
            elapsed = time.perf_counter() - start
            self._metrics.duration_seconds.labels(provider=self._prov_name).observe(
                elapsed
            )
            return out
        except VerifierTimedOut:
            elapsed = time.perf_counter() - start
            self._metrics.timeout_total.labels(provider=self._prov_name).inc()
            self._metrics.duration_seconds.labels(provider=self._prov_name).observe(
                elapsed
            )
            # Preserve external behavior: allow, but mark reason for policy/audit.
            return VerifierOutcome(
                allowed=True, reason="verifier_timeout_budget_exceeded"
            )
