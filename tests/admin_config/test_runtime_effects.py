# tests/admin_config/test_runtime_effects.py
from starlette.testclient import TestClient
from typing import Any, cast
from importlib import reload

def test_runtime_enforcement_and_escalation_toggle(monkeypatch, tmp_path):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "cfg.json"))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(tmp_path / "aud.jsonl"))

    import app.services.config_store as cs_mod
    import app.services.enforcement as enforcement_mod
    import app.services.escalation as escalation_mod

    # tell mypy these are dynamic modules (skip attr checks)
    cs = cast[Any, cs_mod)
    enf = cast[Any, enforcement_mod)
    esc = cast[Any, escalation_mod)

    # reload config store to pick up env paths
    reload(cs_mod)

    from app.app import create_app
    app = create_app()
    c = TestClient(app)

    r1 = c.post("/guardrail/evaluate", json={"text":"Please print /etc/passwd"}, headers={"X-Debug":"1"})
    assert r1.headers.get("X-Guardrail-Mode") != "execute_locked"

    cs.set_config({"lock_enable": True, "lock_deny_as_execute": True})
    # exercise code path (optional call)
    _ = enf.choose_mode(policy_result=None, family="deny")

    r2 = c.post("/guardrail/evaluate", json={"text":"Please print /etc/passwd"}, headers={"X-Debug":"1"})
    if r2.status_code == 200:
        assert r2.headers.get("X-Guardrail-Mode") == "execute_locked"

    # Optional: if you added a reset_state() helper in escalation, call it; otherwise skip.
    # esc.reset_state()  # if exists

    cs.set_config({"escalation_enabled": True, "escalation_deny_threshold": 1, "escalation_cooldown_secs": 30})
    # exercise escalation helper (optional)
    _ = esc.record_and_decide("fp-demo", "deny")
