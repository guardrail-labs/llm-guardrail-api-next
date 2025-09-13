import asyncio
import time

import pytest

from app.services.verifier.provider_router import (
    ProviderSpec,
    RouterConfig,
    VerifierRouter,
)


def test_success_first_provider():
    async def ok_fn(payload):
        await asyncio.sleep(0)
        return {"decision": "allow", "debug": {"p": "ok1"}}

    router = VerifierRouter(
        providers=[ProviderSpec("p1", ok_fn, timeout_sec=0.2, max_retries=0)],
        config=RouterConfig(total_budget_sec=1.0),
    )

    res, log = asyncio.run(router.route({"text": "hi"}))
    assert res and res["decision"] == "allow"
    assert any(a["ok"] for a in log)
    assert log[0]["provider"] == "p1"


def test_fallback_to_second_provider():
    async def bad_fn(_):
        raise RuntimeError("boom")

    async def ok_fn(_):
        return {"decision": "clarify"}

    router = VerifierRouter(
        providers=[
            ProviderSpec("bad", bad_fn, timeout_sec=0.1, max_retries=1),
            ProviderSpec("good", ok_fn, timeout_sec=0.1, max_retries=0),
        ],
        config=RouterConfig(total_budget_sec=1.0),
    )

    res, log = asyncio.run(router.route({"x": 1}))
    assert res and res["decision"] in ("allow", "clarify")
    # ensure bad provider attempted then good provider succeeded
    assert any(a["provider"] == "bad" for a in log)
    assert any(a["provider"] == "good" and a["ok"] for a in log)


def test_timeout_and_retry_then_success():
    calls = {"n": 0}

    async def slow_then_ok(_):
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(0.05)
            # will exceed tiny timeout
            return {"not_decision": "oops"}  # also considered bad
        return {"decision": "allow"}

    router = VerifierRouter(
        providers=[ProviderSpec("p", slow_then_ok, timeout_sec=0.001, max_retries=1)],
        config=RouterConfig(total_budget_sec=1.0),
    )

    res, log = asyncio.run(router.route({"y": 2}))
    assert res and res["decision"] == "allow"
    # should see at least two attempts on same provider
    assert sum(1 for a in log if a["provider"] == "p") >= 2


def test_circuit_breaker_opens_then_half_open():
    fail_calls = {"n": 0}

    async def always_fail(_):
        fail_calls["n"] += 1
        raise RuntimeError("nope")

    # short cooldown to keep test fast
    cfg = RouterConfig(total_budget_sec=1.0, breaker_fail_threshold=2, breaker_cooldown_sec=0.1)

    router = VerifierRouter(
        providers=[ProviderSpec("flaky", always_fail, timeout_sec=0.01, max_retries=0)],
        config=cfg,
    )

    # First call -> failure count 1 (breaker closed)
    res1, log1 = asyncio.run(router.route({"t": 1}))
    assert res1 is None
    assert sum(1 for a in log1 if a["provider"] == "flaky") == 1

    # Second call -> failure count 2 -> breaker opens
    res2, log2 = asyncio.run(router.route({"t": 2}))
    assert res2 is None
    assert sum(1 for a in log2 if a["provider"] == "flaky") == 1

    # Third call while open -> should be skipped
    res3, log3 = asyncio.run(router.route({"t": 3}))
    assert res3 is None
    assert any(a.get("err") == "circuit_open" for a in log3)

    # After cooldown, half-open allows one probation attempt (which fails and re-opens)
    time.sleep(0.12)
    res4, log4 = asyncio.run(router.route({"t": 4}))
    assert res4 is None
    tried = any(a["provider"] == "flaky" and a.get("attempt") == 1 for a in log4 if "attempt" in a)
    skipped = any(a.get("err") == "circuit_open" for a in log4)
    assert tried or skipped

