from app.services.verifier.provider_quota import QuotaSkipRegistry


def test_quota_registry_basic(monkeypatch):
    q = QuotaSkipRegistry()
    assert not q.is_skipped("p")
    dur = q.on_rate_limited("p", 2.0)
    assert 1.0 <= dur <= 600.0
    assert q.is_skipped("p")
    q.clear("p")
    assert not q.is_skipped("p")

