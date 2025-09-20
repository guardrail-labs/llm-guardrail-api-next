from app.services import webhooks as W


def test_horizon_default_independent_of_max_ms(monkeypatch):
    # Lower per-attempt cap, omit horizon on purpose; horizon should still default to 900_000 ms.
    cfg = {
        "webhook_enable": True,
        "webhook_url": "https://example.com/hook",
        "webhook_secret": "x",
        "webhook_backoff_max_ms": 5_000,  # reduce per-attempt cap
        # "webhook_max_horizon_ms" not set -> should default to 900_000
    }

    # Feed runtime config directly to webhooks via the helper the module uses.
    monkeypatch.setattr(W, "_get_cfg_dict", lambda: cfg, raising=True)

    # Ensure env doesn't override in CI.
    monkeypatch.delenv("WEBHOOK_MAX_HORIZON_MS", raising=False)

    base_ms, max_ms, max_attempts, horizon_ms = W._backoff_params()
    assert max_ms == 5_000
    assert horizon_ms == 900_000  # remains 15 minutes by default
