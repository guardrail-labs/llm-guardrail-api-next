from __future__ import annotations

from typing import Callable, Dict, Tuple

import pytest
from prometheus_client import REGISTRY

from app.observability import adjudication_log
from app.routes import guardrail as guardrail_module


class MetricsSnapshot:
    def __init__(self) -> None:
        samples: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        for metric in REGISTRY.collect():
            for sample in metric.samples:
                label_items = tuple(sorted(sample.labels.items()))
                samples[(sample.name, label_items)] = float(sample.value)
        self._samples = samples

    def counter(self, name: str, **labels: str) -> float:
        key = (name, tuple(sorted(labels.items())))
        return self._samples.get(key, 0.0)


@pytest.fixture
def metrics_snapshot() -> Callable[[], MetricsSnapshot]:
    def _snapshot() -> MetricsSnapshot:
        return MetricsSnapshot()

    return _snapshot


def test_multipart_unicode_block_audited_and_counted(
    client,
    metrics_snapshot: Callable[[], MetricsSnapshot],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adjudication_log.clear()

    audit_events: list[dict] = []

    def _capture(payload: Dict[str, object]) -> None:
        audit_events.append(dict(payload))

    monkeypatch.setattr(guardrail_module, "_emit", _capture, raising=False)

    before = metrics_snapshot()

    files = {"file": ("note.txt", "hello\u202eworld")}
    resp = client.post("/guardrail/evaluate_multipart", files=files)
    assert resp.status_code == 200

    body = resp.json()
    assert body.get("action") == "block_input_only"
    assert body.get("reason") == "suspicious_unicode"
    assert resp.headers.get("X-Guardrail-Decision") == "deny"

    after = metrics_snapshot()

    deny_before = before.counter("guardrail_decisions_family_total", family="deny")
    deny_after = after.counter("guardrail_decisions_family_total", family="deny")
    assert deny_after >= deny_before + 1

    suspicious_before = before.counter("guardrail_unicode_suspicious_total", reason="bidi_control")
    suspicious_after = after.counter("guardrail_unicode_suspicious_total", reason="bidi_control")
    assert suspicious_after >= suspicious_before + 1

    assert audit_events, "expected audit payload recorded"
    last_event = audit_events[-1]
    assert last_event.get("direction") == "ingress"
    assert last_event.get("request_id") == resp.headers.get("X-Request-ID")

    records = adjudication_log.query(decision="block_input_only", limit=5)
    assert any(r.request_id == resp.headers.get("X-Request-ID") for r in records)
