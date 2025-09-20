from app.services.webhooks import configure, set_config
from app.services import webhooks as W


def test_horizon_default_independent_of_max_ms(monkeypatch):
    # Lower max backoff, omit horizon on purpose
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "x",
            "webhook_backoff_max_ms": 5_000,  # reduce per-attempt cap
            # "webhook_max_horizon_ms" not set -> should default to 900_000
        }
    )
    configure(reset=True)

    # Ensure env doesn't override; clear any CI env
    monkeypatch.delenv("WEBHOOK_MAX_HORIZON_MS", raising=False)

    base_ms, max_ms, max_attempts, horizon_ms = W._backoff_params()
    assert max_ms == 5_000
    assert horizon_ms == 900_000  # remains 15 minutes by default
