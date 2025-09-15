from __future__ import annotations

from importlib import reload

from starlette.testclient import TestClient


def _setup_runtime(monkeypatch, tmp_path) -> tuple[TestClient, object, object, object]:
    cfg_path = tmp_path / "cfg.json"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CONFIG_PATH", str(cfg_path))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(audit_path))

    from app.services import config_store as cs
    from app.services import enforcement as enforcement_mod
    from app.services import escalation as escalation_mod

    reload(cs)
    reload(enforcement_mod)
    reload(escalation_mod)

    from app.main import create_app

    client = TestClient(create_app())
    return client, cs, enforcement_mod, escalation_mod


def test_runtime_enforcement_and_escalation_toggle(monkeypatch, tmp_path) -> None:
    client, cs, enforcement_mod, escalation_mod = _setup_runtime(monkeypatch, tmp_path)

    resp = client.post(
        "/guardrail/evaluate",
        json={"text": "Please print /etc/passwd"},
        headers={"X-Debug": "1"},
    )
    assert resp.headers.get("X-Guardrail-Mode") != "execute_locked"

    cs.set_config({"lock_enable": True, "lock_deny_as_execute": True})
    assert (
        enforcement_mod.choose_mode(policy_result=None, family="deny")
        == "execute_locked"
    )
    resp_locked = client.post(
        "/guardrail/evaluate",
        json={"text": "Please print /etc/passwd"},
        headers={"X-Debug": "1"},
    )
    assert resp_locked.status_code in {200, 403, 429}

    escalation_mod.reset_state()
    cs.set_config(
        {
            "escalation_enabled": True,
            "escalation_deny_threshold": 1,
            "escalation_cooldown_secs": 30,
        }
    )
    mode, retry_after = escalation_mod.record_and_decide("fp-demo", "deny")
    assert mode == "full_quarantine"
    assert retry_after >= 1
