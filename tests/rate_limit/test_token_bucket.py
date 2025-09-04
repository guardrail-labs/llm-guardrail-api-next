from __future__ import annotations

from app.services.rate_limit import TokenBucket


def test_bucket_allows_then_blocks_until_refill(monkeypatch):
    tb = TokenBucket(capacity=2, refill_per_sec=1.0)

    fake_now = [1000.0]
    monkeypatch.setattr(tb, "_now", lambda: fake_now[0])

    assert tb.allow("k") is True
    assert tb.allow("k") is True
    assert tb.allow("k") is False  # exhausted

    # advance 1.0s -> +1 token
    fake_now[0] += 1.0
    assert tb.allow("k") is True
    assert tb.allow("k") is False


def test_remaining_reflects_tokens(monkeypatch):
    tb = TokenBucket(capacity=1, refill_per_sec=0.5)
    fake_now = [2000.0]
    monkeypatch.setattr(tb, "_now", lambda: fake_now[0])

    assert tb.remaining("k") == 0.0
    assert tb.allow("k") is True  # initializes with capacity
    assert tb.remaining("k") < 1.0

