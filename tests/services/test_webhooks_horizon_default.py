from app.services import webhooks as W
from app.services.config_store import reset_config, set_config
from app.services.webhooks import configure


def test_horizon_default_independent_of_max_ms(monkeypatch):
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "x",
        }
    )
    try:
        configure(reset=True)

        # Lower max backoff via env, omit horizon on purpose
        monkeypatch.setenv("WEBHOOK_BACKOFF_MAX_MS", "5000")
        monkeypatch.delenv("WEBHOOK_MAX_HORIZON_MS", raising=False)

        base_ms, max_ms, max_attempts, horizon_ms = W._backoff_params()  # type: ignore[attr-defined]
        assert max_ms == 5_000
        assert horizon_ms == 900_000  # remains 15 minutes by default
    finally:
        reset_config()
