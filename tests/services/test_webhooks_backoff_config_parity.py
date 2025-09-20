from app.services import webhooks as W
from app.services.config_store import reset_config, set_config
from app.services.webhooks import configure


def test_backoff_uses_runtime_config(monkeypatch):
    set_config(
        {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "x",
            "webhook_backoff_ms": 1,
            "webhook_max_retries": 1,
        }
    )
    configure(reset=True)

    monkeypatch.setattr(W.random, "uniform", lambda a, b: (a + b) / 2.0)
    slept = {"ms": 0}
    monkeypatch.setattr(W, "_sleep_ms", lambda ms: slept.__setitem__("ms", slept["ms"] + ms))

    calls = {"n": 0}

    def send_once():
        calls["n"] += 1
        if calls["n"] == 1:
            return (False, 503, None)
        return (True, 200, None)

    try:
        ok = W._deliver_with_backoff(send_once)
        assert ok is True
        assert slept["ms"] <= 10
    finally:
        reset_config()
