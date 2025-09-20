from __future__ import annotations

from fastapi.testclient import TestClient
from prometheus_client import REGISTRY, generate_latest

from app.main import app
from app.services import mitigation_modes

client = TestClient(app)


def _metric_value(mode: str) -> float:
    text = generate_latest(REGISTRY).decode("utf-8")
    target = f'guardrail_mitigation_override_total{{mode="{mode}"}}'
    for line in text.splitlines():
        if line.startswith(target):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return float(parts[1])
                except ValueError:
                    return 0.0
    return 0.0


def test_block_override_increments_metric() -> None:
    mitigation_modes._reset_for_tests()
    tenant = "metrics-tenant"
    bot = "metrics-bot"
    before = _metric_value("block")
    mitigation_modes.set_modes(
        tenant,
        bot,
        {"block": True, "redact": False, "clarify_first": False},
    )

    resp = client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Tenant-ID": tenant, "X-Bot-ID": bot},
    )

    assert resp.status_code == 200
    payload = resp.json()
    assert payload.get("decision") == "block"
    assert payload.get("mitigation_forced") == "block"

    after = _metric_value("block")
    assert after == before + 1.0


def test_metric_not_incremented_without_override() -> None:
    mitigation_modes._reset_for_tests()
    tenant = "metrics-tenant"
    bot = "metrics-bot"
    before = _metric_value("block")

    resp = client.post(
        "/guardrail/evaluate",
        json={"text": "hello"},
        headers={"X-Tenant-ID": tenant, "X-Bot-ID": bot},
    )

    assert resp.status_code == 200
    payload = resp.json()
    assert payload.get("decision") == "allow"
    assert payload.get("mitigation_forced") is None

    after = _metric_value("block")
    assert after == before
