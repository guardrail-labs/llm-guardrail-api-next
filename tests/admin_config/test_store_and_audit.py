from __future__ import annotations

import json
from importlib import reload


def test_config_persist_and_audit(tmp_path, monkeypatch) -> None:
    cfg_path = tmp_path / "config.json"
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CONFIG_PATH", str(cfg_path))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(audit_path))

    from app.services import config_store as cs

    reload(cs)

    before = cs.get_config()
    assert before["lock_enable"] is False

    after = cs.set_config(
        {"lock_enable": True, "escalation_deny_threshold": 5},
        actor="test",
    )
    assert after["lock_enable"] is True
    assert after["escalation_deny_threshold"] == 5

    saved = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert saved["lock_enable"] is True
    assert saved["escalation_deny_threshold"] == 5

    lines = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    entry = json.loads(lines[-1])
    assert entry["actor"] == "test"
    assert entry["patch"]["lock_enable"] is True
