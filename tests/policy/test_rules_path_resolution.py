from __future__ import annotations

from pathlib import Path

from app.services import policy_loader


def test_rules_path_env_override(monkeypatch, tmp_path):
    policy_loader._cache.clear()
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("version: env-test\n", encoding="utf-8")
    monkeypatch.setenv("GUARDRAIL_RULES_PATH", str(rules_file))

    blob = policy_loader.reload_now()

    assert Path(blob.path) == rules_file
    assert blob.version == "env-test"
