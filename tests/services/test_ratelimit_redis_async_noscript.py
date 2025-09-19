from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.observability.metrics import GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL
from app.services import ratelimit_backends as rb, ratelimit_backends_async as rba

pytestmark = pytest.mark.asyncio


def _metric_value() -> float:
    samples = list(GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL.collect())
    if not samples:
        return 0.0
    sample = samples[0].samples
    if not sample:
        return 0.0
    return float(sample[0].value)


def _make_client() -> Any:
    client = AsyncMock()
    client.eval.return_value = ["1", "0", "9"]
    return client


async def test_happy_path_evalsha_no_reload() -> None:
    client = _make_client()
    client.script_load.return_value = "sha1"
    client.evalsha.return_value = ["1", "0", "9"]

    bucket = rba.AsyncRedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = await bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert _metric_value() == before


async def test_noscript_reloads_and_retry_succeeds_increments_counter() -> None:
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT"), ["1", "0", "9"]]

    bucket = rba.AsyncRedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = await bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert bucket._get_sha() == "sha2"
    assert _metric_value() == pytest.approx(before + 1)


async def test_reload_fails_fall_back_to_eval() -> None:
    client = _make_client()
    client.script_load.side_effect = ["sha1", rb.RedisError("load failed")]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT")]

    bucket = rba.AsyncRedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = await bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert client.eval.await_count == 1
    assert _metric_value() == before


async def test_reload_succeeds_but_retry_noscript_again_fall_back_to_eval_no_counter_inc() -> None:
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [
        rb.NoScriptError("NOSCRIPT"),
        rb.NoScriptError("NOSCRIPT-again"),
    ]

    bucket = rba.AsyncRedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = await bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert _metric_value() == before


async def test_reload_succeeds_but_retry_non_noscript_propagates_without_eval_or_counter() -> None:
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT"), rb.RedisError("OOM")]

    bucket = rba.AsyncRedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    redis_key = bucket._key("key")
    with pytest.raises(rb.RedisError):
        await bucket._call_script(redis_key, now=123.456, rps=5.0, burst=10.0, cost=1.0)

    assert client.eval.await_count == 0
    assert _metric_value() == before
