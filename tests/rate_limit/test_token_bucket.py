from __future__ import annotations

from app.services.rate_limit import TokenBucket


def test_bucket_allows_then_blocks_until_refill(monkeypatch):
    tb = TokenBucket(capacity=2, refill_per_sec=1.0)

    fake_now = [1000.0]
    monkeypatch.setattr(tb, "_now", lambda: fake_now[0])

    assert tb.allow("k") is True
    assert tb.allow("k") is True
    assert tb.allow("k") is False  # exhausted

    # advance 1s => +1 token
    fake_now[0] += 1.0
    assert tb.allow("k") is True
    assert tb.allow("k") is False


def test_estimate_wait_seconds(monkeypatch):
    tb = TokenBucket(capacity=1, refill_per_sec=2.0)  # 2 tokens/sec
    fake_now = [2000.0]
    monkeypatch.setattr(tb, "_now", lambda: fake_now[0])

    # first call initializes with capacity and consumes it
    assert tb.allow("k") is True
    # now empty; need 0.5s for next token
    wait = tb.estimate_wait_seconds("k")
    assert 0.0 < wait <= 0.6

    fake_now[0] += 0.5
    assert tb.allow("k") is True

