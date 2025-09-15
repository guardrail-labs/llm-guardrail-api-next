from __future__ import annotations

import json
from importlib import reload

import app.services.config_store as cs


def test_config_persist_and_audit(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    aud = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CONFIG_PATH", str(cfg))
    monkeypatch.setenv("CONFIG_AUDIT_PATH", str(aud))

    # defaults
    reload(cs)
    before = cs.get_config()
    assert before["lock_enable"] is False

    after = cs.set_config(
        {"lock_enable": True, "escalation_deny_threshold": 5}, actor="test"
    )
    assert after["lock_enable"] is True
    assert after["escalation_deny_threshold"] == 5

    saved = json.loads(cfg.read_text(encoding="utf-8"))
    assert saved["lock_enable"] is True

    lines = aud.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
