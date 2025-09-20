import importlib

from app.services import webhooks as W


def _counter_value(counter, *labels: str) -> float:
    metrics = getattr(counter, "_metrics", None)
    if isinstance(metrics, dict):
        child = metrics.get(tuple(labels))
        if child is None:
            return 0.0
        return float(child._value.get())
    value = getattr(counter, "_value", None)
    return float(value.get()) if value is not None else 0.0


def test_cb_open_preflight_aborts_without_http(monkeypatch):
    import app.observability.metrics as metrics

    importlib.reload(metrics)
    importlib.reload(W)

    events: list[str] = []
    monkeypatch.setattr(W, "_dlq_write", lambda evt, reason: events.append(reason))

    class StubRegistry:
        def __init__(self) -> None:
            self.calls = 0

        def should_dlq_now(self, url: str) -> bool:
            self.calls += 1
            return True

        def on_success(self, url: str) -> None:  # pragma: no cover - defensive
            raise AssertionError("should not be called when breaker is open")

        def on_failure(self, url: str) -> None:  # pragma: no cover - defensive
            raise AssertionError("should not be called when breaker is open")

    stub = StubRegistry()
    monkeypatch.setattr(W, "get_cb_registry", lambda: stub)
    monkeypatch.setattr(
        W,
        "get_config",
        lambda: {
            "webhook_enable": True,
            "webhook_url": "https://example.com/hook",
            "webhook_secret": "",
            "webhook_timeout_ms": 1000,
            "webhook_allow_insecure_tls": False,
            "webhook_allowlist_host": "",
        },
    )

    class FailClient:
        def __init__(self, *args, **kwargs) -> None:  # pragma: no cover - defensive
            raise AssertionError("HTTP client should not be created when breaker is open")

    monkeypatch.setattr(W.httpx, "Client", FailClient)

    abort_before = _counter_value(metrics.webhook_abort_total, "cb_open")

    outcome, status, client, client_conf = W._deliver_with_client(
        {"id": "evt"}, client=None, client_conf=None
    )

    assert outcome == "cb_open"
    assert status == "-"
    assert client is None
    assert client_conf is None
    assert stub.calls == 1
    assert events == ["cb_open"]
    assert _counter_value(metrics.webhook_abort_total, "cb_open") - abort_before == 1
