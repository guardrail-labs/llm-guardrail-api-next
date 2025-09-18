from unittest.mock import MagicMock

import pytest

from app.observability.metrics import guardrail_ratelimit_redis_script_reload_total
from app.services import ratelimit_backends as rb


def _metric_value() -> float:
    samples = list(guardrail_ratelimit_redis_script_reload_total.collect())
    if not samples:
        return 0.0
    sample = samples[0].samples
    if not sample:
        return 0.0
    return sample[0].value


def _make_client():
    client = MagicMock()
    client.eval.return_value = ["1", "0", "9"]
    return client


def test_happy_path_evalsha_no_reload():
    client = _make_client()
    client.script_load.return_value = "sha1"
    client.evalsha.return_value = ["1", "0", "9"]

    bucket = rb.RedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert _metric_value() == before


def test_noscript_reloads_and_retry_succeeds_increments_counter():
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT"), ["1", "0", "9"]]

    bucket = rb.RedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert bucket._get_sha() == "sha2"
    assert _metric_value() == pytest.approx(before + 1)


def test_reload_fails_fall_back_to_eval():
    client = _make_client()
    client.script_load.side_effect = ["sha1", rb.RedisError("load failed")]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT")]

    bucket = rb.RedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert _metric_value() == before


def test_reload_succeeds_but_retry_noscript_again_fall_back_to_eval_no_counter_inc():
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [rb.NoScriptError("NOSCRIPT"), rb.NoScriptError("NOSCRIPT-again")]

    bucket = rb.RedisTokenBucket(client, prefix="test:")

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=10.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining == 9.0
    assert bucket._get_sha() == "sha2"
    assert _metric_value() == before
