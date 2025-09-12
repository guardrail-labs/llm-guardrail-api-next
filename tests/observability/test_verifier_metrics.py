from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from prometheus_client import CollectorRegistry

from app.observability.metrics import make_verifier_metrics
from app.services.verifier.result_types import VerifierOutcome
from app.services.verifier.router_adapter import VerifierAdapter


@dataclass
class _ProbeProvider:
    delay_ms: int = 0
    calls: int = field(default=0, init=False)
    name: Optional[str] = "probe"

    async def evaluate(self, text: str) -> VerifierOutcome:
        self.calls += 1
        if self.delay_ms:
            await asyncio.sleep(self.delay_ms / 1000.0)
        return VerifierOutcome(allowed=True, reason="ok", provider="probe")


def _sample_value(counter, provider: str) -> float:
    # Prometheus client exposes samples via .collect()
    fam = list(counter.collect())[0]
    for s in fam.samples:
        if s.labels.get("provider") == provider:
            return float(s.value)
    return 0.0


def _hist_count(hist, provider: str) -> float:
    fam = list(hist.collect())[0]
    # count is the sample with suffix _count
    for s in fam.samples:
        if s.name.endswith("_count") and s.labels.get("provider") == provider:
            return float(s.value)
    return 0.0


def test_metrics_skip_path(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0.25")
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    provider = _ProbeProvider()
    adapter = VerifierAdapter(provider, rng=lambda: 0.99, metrics=metrics)

    out = asyncio.run(adapter.evaluate("x"))
    assert out.allowed is True
    assert provider.calls == 0

    assert _sample_value(metrics.sampled_total, "probe") == 0.0
    assert _sample_value(metrics.skipped_total, "probe") == 1.0
    assert _sample_value(metrics.timeout_total, "probe") == 0.0
    assert _hist_count(metrics.duration_seconds, "probe") == 0.0


def test_metrics_sample_success(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "50")

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    provider = _ProbeProvider(delay_ms=5)
    adapter = VerifierAdapter(provider, rng=lambda: 0.0, metrics=metrics)

    out = asyncio.run(adapter.evaluate("y"))
    assert out.allowed is True
    assert provider.calls == 1

    assert _sample_value(metrics.sampled_total, "probe") == 1.0
    assert _sample_value(metrics.skipped_total, "probe") == 0.0
    assert _sample_value(metrics.timeout_total, "probe") == 0.0
    # One observation recorded
    assert _hist_count(metrics.duration_seconds, "probe") == 1.0


def test_metrics_timeout(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.0")
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "1")

    reg = CollectorRegistry()
    metrics = make_verifier_metrics(reg)
    provider = _ProbeProvider(delay_ms=10)
    adapter = VerifierAdapter(provider, rng=lambda: 0.0, metrics=metrics)

    out = asyncio.run(adapter.evaluate("z"))
    assert out.allowed is True  # external behavior unchanged on timeout
    # Provider may or may not complete before timeout; we only care about metrics.
    assert _sample_value(metrics.sampled_total, "probe") == 1.0
    assert _sample_value(metrics.skipped_total, "probe") == 0.0
    assert _sample_value(metrics.timeout_total, "probe") == 1.0
    assert _hist_count(metrics.duration_seconds, "probe") == 1.0
