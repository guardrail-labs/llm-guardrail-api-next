import logging
from typing import Tuple
from unittest.mock import MagicMock

import pytest
from redis.exceptions import NoScriptError, RedisError

from app.observability.metrics import guardrail_ratelimit_redis_script_reload_total
from app.services.ratelimit_backends import RedisTokenBucket


@pytest.fixture(autouse=True)
def disable_logging_noise():
    logger = logging.getLogger("app.services.ratelimit_backends")
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    yield
    logger.setLevel(previous)


def _metric_value() -> float:
    metric = next(iter(guardrail_ratelimit_redis_script_reload_total.collect()), None)
    if not metric or not metric.samples:
        return 0.0
    return float(metric.samples[0].value)


def _make_client(script_sha: str = "sha1") -> MagicMock:
    client = MagicMock()
    client.script_load.return_value = script_sha
    client.eval = MagicMock()
    return client


def _make_bucket(client: MagicMock) -> RedisTokenBucket:
    bucket = RedisTokenBucket(client, prefix="rl:")
    return bucket


def _default_result() -> Tuple[str, str, str]:
    return ("1", "0", "0")


def test_happy_path_evalsha_no_reload():
    client = _make_client()
    client.evalsha.return_value = _default_result()
    bucket = _make_bucket(client)

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("k", cost=1.0, rps=1.0, burst=1.0)
    after = _metric_value()

    assert allowed is True
    assert retry_after == pytest.approx(0.0)
    assert remaining == pytest.approx(0.0)
    assert after == before
    client.script_load.assert_called_once()
    client.evalsha.assert_called_once()


def test_noscript_triggers_reload_and_retry_success():
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [NoScriptError("NOSCRIPT"), _default_result()]
    bucket = _make_bucket(client)

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("k", cost=1.0, rps=1.0, burst=1.0)
    after = _metric_value()

    assert allowed is True
    assert retry_after == pytest.approx(0.0)
    assert remaining == pytest.approx(0.0)
    assert after == pytest.approx(before + 1)
    assert bucket._sha == "sha2"
    assert client.script_load.call_count == 2
    assert client.evalsha.call_count == 2

    # Subsequent calls should reuse cached SHA without another load.
    client.evalsha.side_effect = None
    client.evalsha.return_value = _default_result()
    allowed, _, _ = bucket.allow("k", cost=1.0, rps=1.0, burst=1.0)
    assert allowed is True
    assert client.script_load.call_count == 2


def test_reload_failure_triggers_fallback(monkeypatch):
    client = _make_client()
    client.script_load.side_effect = ["sha1", RedisError("load failed")]
    client.evalsha.side_effect = [NoScriptError("NOSCRIPT"), _default_result()]
    bucket = _make_bucket(client)

    fallback_result = (False, 0.0, None)

    class _Fallback:
        def allow(self, *args, **kwargs):
            return fallback_result

    monkeypatch.setattr(bucket, "_fallback", _Fallback())

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("k", cost=1.0, rps=1.0, burst=1.0)
    after = _metric_value()

    assert allowed is fallback_result[0]
    assert retry_after == pytest.approx(fallback_result[1])
    assert remaining is fallback_result[2]
    assert client.eval.call_count == 0
    assert after == before


def test_retry_failure_after_reload_triggers_fallback(monkeypatch):
    client = _make_client()
    client.script_load.side_effect = ["sha1", "sha2"]
    client.evalsha.side_effect = [NoScriptError("NOSCRIPT"), RedisError("eval failed")]
    bucket = _make_bucket(client)

    fallback_result = (False, 0.0, None)

    class _Fallback:
        def allow(self, *args, **kwargs):
            return fallback_result

    monkeypatch.setattr(bucket, "_fallback", _Fallback())

    before = _metric_value()
    allowed, retry_after, remaining = bucket.allow("k", cost=1.0, rps=1.0, burst=1.0)
    after = _metric_value()

    assert allowed is fallback_result[0]
    assert retry_after == pytest.approx(fallback_result[1])
    assert remaining is fallback_result[2]
    assert after == before
    # SHA should still be updated even though retry failed, so future attempts
    # will try the reloaded script again.
    assert bucket._sha == "sha2"
