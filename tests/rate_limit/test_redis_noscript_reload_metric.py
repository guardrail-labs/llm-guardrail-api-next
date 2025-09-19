from __future__ import annotations

import prometheus_client
import pytest

from app.observability import metrics as observability_metrics
from app.services import ratelimit_backends as rb


@pytest.fixture(autouse=True)
def reset_ratelimit_reload_counter():
    counter = observability_metrics.GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL
    _reset_counter(counter)
    yield
    _reset_counter(counter)


def _reset_counter(counter) -> None:
    value = getattr(counter, "_value", None)
    if value is not None:
        try:
            value.set(0)
        except Exception:
            pass
    samples = getattr(counter, "_samples", None)
    if samples is not None:
        try:
            samples.clear()
        except Exception:
            pass


def _metric_text() -> str:
    return prometheus_client.generate_latest(prometheus_client.REGISTRY).decode("utf-8")


class _ReloadOnceRedis:
    def __init__(self) -> None:
        self.evalsha_calls: list[str] = []
        self.script_load_calls = 0

    def script_load(self, lua: str):
        self.script_load_calls += 1
        return f"sha{self.script_load_calls}"

    def evalsha(self, sha, numkeys, *args):
        self.evalsha_calls.append(sha)
        if len(self.evalsha_calls) == 1:
            raise rb.NoScriptError("NOSCRIPT No matching script.")
        return ["1", "0", "0"]

    def eval(self, *args, **kwargs):
        raise AssertionError("eval should not be used after successful reload")


def test_metric_increments_on_noscript_reload():
    client = _ReloadOnceRedis()
    bucket = rb.RedisTokenBucket(client, prefix="test:")

    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=5.0)

    assert allowed is True
    assert retry_after == 0.0
    assert remaining >= 0.0

    text = _metric_text()
    assert "guardrail_ratelimit_redis_script_reload_total 1.0" in text


def test_metric_does_not_increment_on_other_errors():
    class _BoomRedis:
        def script_load(self, lua: str):
            return "sha"

        def evalsha(self, *args, **kwargs):
            raise rb.RedisError("boom")

    bucket = rb.RedisTokenBucket(_BoomRedis(), prefix="test:")

    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=1.0, burst=0.0)

    assert allowed in (True, False)
    assert retry_after >= 0.0
    assert remaining is not None

    text = _metric_text()
    assert "guardrail_ratelimit_redis_script_reload_total 1.0" not in text


def test_metric_not_incremented_on_subsequent_calls_after_reload():
    client = _ReloadOnceRedis()
    bucket = rb.RedisTokenBucket(client, prefix="test:")

    allowed, retry_after, remaining = bucket.allow("key", cost=1.0, rps=5.0, burst=5.0)
    assert allowed is True
    assert retry_after == 0.0
    assert remaining >= 0.0

    text = _metric_text()
    assert "guardrail_ratelimit_redis_script_reload_total 1.0" in text

    allowed_again, retry_after_again, remaining_again = bucket.allow(
        "key", cost=1.0, rps=5.0, burst=5.0
    )

    assert allowed_again is True
    assert retry_after_again == 0.0
    assert remaining_again >= 0.0
    assert client.script_load_calls == 2

    text = _metric_text()
    assert "guardrail_ratelimit_redis_script_reload_total 1.0" in text
    assert "guardrail_ratelimit_redis_script_reload_total 2.0" not in text
