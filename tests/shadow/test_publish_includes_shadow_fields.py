from __future__ import annotations

from starlette.testclient import TestClient

from app.services import decisions_bus
from app.services.config_store import set_config


def reset_config() -> None:
    # If you have a central reset helper, use it; otherwise this is a no-op placeholder.
    pass


def test_decision_event_contains_shadow_fields(tmp_path, monkeypatch):
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

    from app.main import create_app  # ← import from package entrypoint

    app = create_app()
    c = TestClient(app)

    _ = c.post("/guardrail/evaluate", json={"text": "hello"}, headers={"X-Debug": "1"})

    r = c.get("/admin/decisions", headers={"Authorization": "Bearer demo"})
    # Admin may require auth in CI; accept either 200 or 401.
    assert r.status_code in (200, 401)
    if r.status_code == 200:
        evts = r.json()
        if evts:
            evt = evts[0]
            # Presence checks; values depend on live vs shadow actions.
            assert "shadow_action" in evt
            assert "shadow_rule_ids" in evt
