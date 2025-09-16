from __future__ import annotations

from starlette.testclient import TestClient

from app.services import decisions_bus
from app.services.config_store import reset_config, set_config


def test_shadow_disagreement_increments(tmp_path, monkeypatch):
    reset_config()
    monkeypatch.setenv("ADMIN_UI_TOKEN", "demo")
    decisions_bus.configure(path=str(tmp_path / "decisions.jsonl"), reset=True)

    shadow_path = tmp_path / "shadow_policy.json"
    shadow_path.write_text('{"default_action": "deny"}', encoding="utf-8")

    set_config(
        {
            "shadow_enable": True,
            "shadow_policy_path": str(shadow_path),
            "shadow_timeout_ms": 100,
            "shadow_sample_rate": 1.0,
        }
    )

    from app.app import create_app

    app = create_app()
    client = TestClient(app)

    client.post("/guardrail/evaluate", json={"text": "hello world"}, headers={"X-Debug": "1"})
    metrics_text = client.get("/metrics").text

    assert "guardrail_policy_disagreement_total" in metrics_text
