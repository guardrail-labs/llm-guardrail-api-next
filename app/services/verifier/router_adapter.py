# app/services/verifier/router_adapter.py
# Summary (PR-O: Circuit breaker wiring + sampling + latency budget):
# - Keeps existing behavior: sampling (0..1), optional latency budget in ms.
# - NEW: Optional circuit breaker around provider.evaluate when VERIFIER_CB_ENABLED=1.
#   * If breaker is OPEN and deny call -> skip verifier (allowed=True) with reason "circuit_open".
#   * Failures/timeouts record failure; successes record success.
# - No API/response changes elsewhere. Defaults remain: breaker disabled unless enabled via env.

from __future__ import annotations

import asyncio
import random
from typing import Optional

from app.services.circuit_breaker import CircuitBreaker, breaker_from_env
from app.services.verifier.types import VerifierOutcome  # assumed existing


class VerifierAdapter:
    """
    Applies probabilistic sampling and optional latency budget around a verifier provider.

    Parameters
    ----------
    provider : object with `async def evaluate(self, text: str) -> VerifierOutcome`
    sampling_pct : float in [0.0, 1.0]
    latency_budget_ms : Optional[int]
        If <= 0 or None, no timeout is applied.
    """

    def __init__(
        self,
        provider,
        sampling_pct: Optional[float] = None,
        latency_budget_ms: Optional[int] = None,
        **kwargs,  # tolerate extra kwargs from older/newer call sites
    ) -> None:
        self._provider = provider

        # Coalesce/clamp sampling percentage
        sp = 0.0 if sampling_pct is None else float(sampling_pct)
        if sp != sp:  # NaN
            sp = 0.0
        self.sampling_pct = min(1.0, max(0.0, sp))

        # Coalesce budget aliases if present
        lb = latency_budget_ms
        if lb is None and "budget_ms" in kwargs:
            try:
                lb = int(kwargs["budget_ms"])  # legacy alias
            except Exception:
                lb = None
        if lb is not None and lb <= 0:
            lb = None
        self.latency_budget_ms = lb

        # Circuit breaker (off by default; driven by env)
        enabled, breaker = breaker_from_env()
        self._cb_enabled: bool = enabled
        self._cb: CircuitBreaker = breaker

        # Local RNG for sampling
        self._rng = random.Random()

    async def evaluate(self, text: str) -> VerifierOutcome:
        # Respect sampling: <= 0 means never call provider
        if self.sampling_pct <= 0.0:
            return VerifierOutcome(allowed=True, reason="sampling=0.0 (skipped)")

        # Probabilistic draw
        draw = self._rng.random()
        if draw >= self.sampling_pct:
            return VerifierOutcome(
                allowed=True,
                reason=f"sampling_draw={draw:.3f}>=pct={self.sampling_pct:.3f} (skipped)",
            )

        # Circuit breaker gate
        if self._cb_enabled and not self._cb.allow_call():
            return VerifierOutcome(allowed=True, reason="circuit_open (skipped)")

        async def _call() -> VerifierOutcome:
            return await self._provider.evaluate(text)

        try:
            if self.latency_budget_ms is not None:
                timeout_s = max(self.latency_budget_ms / 1000.0, 0.0)
                outcome = await asyncio.wait_for(_call(), timeout=timeout_s)
            else:
                outcome = await _call()
        except asyncio.TimeoutError:
            # Budget exceeded -> mark as failure and allow by default
            if self._cb_enabled:
                self._cb.record_failure()
            return VerifierOutcome(allowed=True, reason="verifier_timeout (skipped)")
        except Exception as exc:  # provider error -> failure, allow request
            if self._cb_enabled:
                self._cb.record_failure()
            return VerifierOutcome(allowed=True, reason=f"verifier_error: {type(exc).__name__}")
        else:
            if self._cb_enabled:
                self._cb.record_success()
            return outcome
