# app/services/verifier/router_adapter.py
# Summary (PR-O final):
# - Probabilistic sampling with injectable RNG.
# - Latency budget via within_budget() + VerifierTimedOut.
# - Metrics preserved (skipped/sample/timeout/duration).
# - Optional circuit breaker (env-gated) that skips when open and records success/failure.
# - Defaults pull from config_sanitizer; ctor args can override without breaking callers.

from __future__ import annotations

import random
import time
from typing import Callable, Optional, Protocol, runtime_checkable

from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_sampling_pct,
)
from app.services.circuit_breaker import breaker_from_env, CircuitBreaker
from app.services.verifier.types import VerifierOutcome
from app.services.verifier.within_budget import VerifierTimedOut, within_budget
from app.services.verifier.metrics import VERIFIER_METRICS


# --------------------------- typing helpers -----------------------------------


class _Counter(Protocol):
    def labels(self, **kwargs) -> "_Counter": ...
    def inc(self, amount: float = 1.0) -> None: ...


class _Histogram(Protocol):
    def labels(self, **kwargs) -> "_Histogram": ...
    def observe(self, value: float) -> None: ...


class VerifierMetrics(Protocol):
    skipped_total: _Counter
    sampled_total: _Counter
    timeout_total: _Counter
    duration_seconds: _Histogram


@runtime_checkable
class _Provider(Protocol):
    async def evaluate(self, text: str) -> VerifierOutcome: ...


def _derive_provider_name(provider: object) -> str:
    # Try a friendly name; fall back to class name.
    name = getattr(provider, "name", None)
    if isinstance(name, str) and name:
        return name
    cls = provider.__class__.__name__
    return cls.replace("Provider", "").lower() or "provider"


def _clamp_pct(x: float) -> float:
    return 0.0 if x != x else min(1.0, max(0.0, x))  # handles NaN


# ------------------------------ adapter ---------------------------------------


class VerifierAdapter:
    """
    Applies sampling and optional latency budget around a verifier provider.
    By default, sampling/budget come from config_sanitizer; constructor args
    can override per-instance.

    Parameters
    ----------
    provider : object implementing `async def evaluate(self, text: str) -> VerifierOutcome`
    rng : Optional[Callable[[], float]]
        Random source in [0, 1). Defaults to random.random.
    metrics : Optional[VerifierMetrics]
        Prometheus-like metrics sink; defaults to VERIFIER_METRICS.
    provider_name : Optional[str]
        Name label for metrics; derived from provider when omitted.
    sampling_pct : Optional[float]
        Override [0..1]. If None, uses get_verifier_sampling_pct().
    latency_budget_ms : Optional[int]
        Override budget in ms. <= 0 treated as unset. If None, uses
        get_verifier_latency_budget_ms(). Legacy alias `budget_ms` in kwargs.
    """

    def __init__(
        self,
        provider: _Provider,
        *,
        rng: Optional[Callable[[], float]] = None,
        metrics: Optional[VerifierMetrics] = None,
        provider_name: Optional[str] = None,
        sampling_pct: Optional[float] = None,
        latency_budget_ms: Optional[int] = None,
        **kwargs: object,
    ) -> None:
        self._provider = provider
        self._rng: Callable[[], float] = rng if rng is not None else random.random
        self._metrics: VerifierMetrics = metrics if metrics is not None else VERIFIER_METRICS
        self._prov_name = provider_name or _derive_provider_name(provider)

        # Optional overrides; None => use config helpers at call time.
        self._sampling_override: Optional[float] = (
            _clamp_pct(float(sampling_pct)) if sampling_pct is not None else None
        )

        lb = latency_budget_ms
        if lb is None and "budget_ms" in kwargs:
            try:
                lb = int(kwargs["budget_ms"])  # legacy alias
            except Exception:
                lb = None
        if lb is not None and lb <= 0:
            lb = None
        self._budget_override: Optional[int] = lb

        # Circuit breaker (off by default; env-driven)
        enabled, breaker = breaker_from_env()
        self._cb_enabled: bool = enabled
        self._cb: CircuitBreaker = breaker

    # ----- dynamic config views (override -> config fallback) -----

    @property
    def sampling_pct(self) -> float:
        if self._sampling_override is not None:
            return self._sampling_override
        return get_verifier_sampling_pct()

    @property
    def budget_ms(self) -> Optional[int]:
        if self._budget_override is not None:
            return self._budget_override
        return get_verifier_latency_budget_ms()

    # ------------------------------- core --------------------------------------

    async def evaluate(self, text: str) -> VerifierOutcome:
        sp = self.sampling_pct

        # Respect sampling: <= 0 -> never call provider
        if sp <= 0.0:
            self._metrics.skipped_total.labels(provider=self._prov_name).inc()
            return VerifierOutcome(allowed=True, reason="sampling=0.0 (skipped)")

        # Probabilistic gate: call only when draw < sampling_pct
        draw = self._rng()
        if not (0.0 <= draw < sp):
            self._metrics.skipped_total.labels(provider=self._prov_name).inc()
            return VerifierOutcome(
                allowed=True,
                reason=f"sampling_draw={draw:.3f}>=pct={sp:.3f} (skipped)",
            )

        # Sampled path
        self._metrics.sampled_total.labels(provider=self._prov_name).inc()

        # Circuit breaker gate
        if self._cb_enabled and not self._cb.allow_call():
            # Count as skipped for now; dedicated circuit metric could be added later.
            self._metrics.skipped_total.labels(provider=self._prov_name).inc()
            return VerifierOutcome(allowed=True, reason="circuit_open (skipped)")

        async def _call() -> VerifierOutcome:
            return await self._provider.evaluate(text)

        start = time.perf_counter()
        try:
            out = await within_budget(_call, budget_ms=self.budget_ms)
            elapsed = time.perf_counter() - start
            self._metrics.duration_seconds.labels(provider=self._prov_name).observe(elapsed)
            if self._cb_enabled:
                self._cb.record_success()
            return out
        except VerifierTimedOut:
            elapsed = time.perf_counter() - start
            self._metrics.timeout_total.labels(provider=self._prov_name).inc()
            self._metrics.duration_seconds.labels(provider=self._prov_name).observe(elapsed)
            if self._cb_enabled:
                self._cb.record_failure()
            # Preserve external behavior: allow, but mark reason for policy/audit.
            return VerifierOutcome(allowed=True, reason="verifier_timeout_budget_exceeded")
        except Exception as exc:
            if self._cb_enabled:
                self._cb.record_failure()
            return VerifierOutcome(allowed=True, reason=f"verifier_error: {type(exc).__name__}")
