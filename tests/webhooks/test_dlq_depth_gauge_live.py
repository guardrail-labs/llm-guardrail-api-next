from typing import Any, Callable, List

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import metrics


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    def _factory() -> Any:
        return create_app()

    return _factory


def _gauge_values(metrics_text: str, name: str) -> List[float]:
    values: List[float] = []
    for line in metrics_text.splitlines():
        if not line.startswith(name):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            values.append(float(parts[-1]))
        except ValueError:
            continue
    return values


def test_dlq_depth_gauge_updates_on_push_without_admin_call(
    app_factory: Callable[[], Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from app.services import webhooks as wh
    from app.services import webhooks_dlq as dlq

    dlq_path = tmp_path / "dlq.jsonl"
    monkeypatch.setenv("WEBHOOK_DLQ_PATH", str(dlq_path))
    monkeypatch.setattr(wh, "_DLQ_PATH", str(dlq_path), raising=False)

    metrics.webhook_dlq_length_set(0)
    metrics.webhook_dlq_depth.set(0)
    wh.configure(reset=True)

    client = TestClient(app_factory())
    try:
        # Trigger gauge updates by appending DLQ entries directly.
        dlq.push(1, {"request_id": "r1"}, "test")
        dlq.push(2, {"request_id": "r2"}, "test")

        metrics_text = client.get("/metrics").text
        values = _gauge_values(metrics_text, "guardrail_webhook_dlq_depth")
        assert values, metrics_text
        assert any(v >= 2 for v in values), values
    finally:
        wh.shutdown()
        dlq.purge_all()
        metrics.webhook_dlq_length_set(0)
        metrics.webhook_dlq_depth.set(0)


def test_dlq_depth_gauge_resets_on_purge_and_retry(
    app_factory: Callable[[], Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from app.services import webhooks as wh
    from app.services import webhooks_dlq as dlq

    dlq_path = tmp_path / "dlq.jsonl"
    monkeypatch.setenv("WEBHOOK_DLQ_PATH", str(dlq_path))
    monkeypatch.setattr(wh, "_DLQ_PATH", str(dlq_path), raising=False)

    metrics.webhook_dlq_length_set(0)
    metrics.webhook_dlq_depth.set(0)
    wh.configure(reset=True)

    client = TestClient(app_factory())
    monkeypatch.setattr(wh, "_ensure_worker", lambda require_enabled: None, raising=False)
    try:
        dlq.push(3, {"request_id": "r3"}, "test")
        dlq.push(4, {"request_id": "r4"}, "test")

        dlq.purge_all()
        metrics_text = client.get("/metrics").text
        values = _gauge_values(metrics_text, "guardrail_webhook_dlq_depth")
        assert values, metrics_text
        assert any(v == pytest.approx(0) for v in values), values

        dlq.push(5, {"request_id": "r5"}, "test")
        dlq.push(6, {"request_id": "r6"}, "test")

        dlq.retry_all()
        metrics_text = client.get("/metrics").text
        values = _gauge_values(metrics_text, "guardrail_webhook_dlq_depth")
        assert values, metrics_text
        assert any(v == pytest.approx(0) for v in values), values
    finally:
        wh.shutdown()
        dlq.purge_all()
        metrics.webhook_dlq_length_set(0)
        metrics.webhook_dlq_depth.set(0)
