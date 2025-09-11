from __future__ import annotations

from app.services.config_sanitizer import (
    get_verifier_latency_budget_ms,
    get_verifier_retry_budget,
    get_verifier_sampling_pct,
)


def test_latency_budget_parsing(monkeypatch) -> None:
    monkeypatch.delenv("VERIFIER_LATENCY_BUDGET_MS", raising=False)
    assert get_verifier_latency_budget_ms() is None

    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "200.5")
    assert get_verifier_latency_budget_ms() == 200

    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "0")
    assert get_verifier_latency_budget_ms() is None

    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "-10")
    assert get_verifier_latency_budget_ms() is None

    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "junk")
    assert get_verifier_latency_budget_ms() is None


def test_retry_budget_parsing(monkeypatch) -> None:
    monkeypatch.delenv("VERIFIER_RETRY_BUDGET", raising=False)
    assert get_verifier_retry_budget() == 0

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "3")
    assert get_verifier_retry_budget() == 3

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "-1")
    assert get_verifier_retry_budget() == 0

    monkeypatch.setenv("VERIFIER_RETRY_BUDGET", "abc")
    assert get_verifier_retry_budget() == 0


def test_sampling_pct_parsing(monkeypatch) -> None:
    monkeypatch.delenv("VERIFIER_SAMPLING_PCT", raising=False)
    assert get_verifier_sampling_pct() == 0.0

    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "0.25")
    assert get_verifier_sampling_pct() == 0.25

    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "1.5")
    assert get_verifier_sampling_pct() == 1.0

    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "-0.1")
    assert get_verifier_sampling_pct() == 0.0

    monkeypatch.setenv("VERIFIER_SAMPLING_PCT", "nan")
    assert get_verifier_sampling_pct() == 0.0
