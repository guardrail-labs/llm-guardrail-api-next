from importlib import reload
from typing import List

from app.admin_config import demo_seed
from app.services.config_store import Binding, BindingsDoc


def test_seed_runs_when_enabled(monkeypatch):
    monkeypatch.setenv("DEMO_DEFAULT_BINDINGS", "true")

    bindings: List[Binding] = []

    def fake_load() -> BindingsDoc:
        return BindingsDoc(version="1", bindings=list(bindings))

    def fake_save(new_bindings: List[Binding], version: str | None = None) -> BindingsDoc:
        bindings.clear()
        bindings.extend(new_bindings)
        return BindingsDoc(version="1", bindings=list(new_bindings))

    saved_payloads = []

    monkeypatch.setattr(demo_seed.config_store, "load_bindings", fake_load)
    monkeypatch.setattr(demo_seed.config_store, "save_bindings", fake_save)
    monkeypatch.setattr(demo_seed, "propagate_bindings", saved_payloads.append)

    reload(demo_seed.config)
    demo_seed.seed_demo_defaults()

    assert {b["rules_path"] for b in bindings} == {"pii_redact", "secrets_redact"}
    assert saved_payloads  # propagation triggered once

    saved_payloads.clear()
    demo_seed.seed_demo_defaults()
    assert not saved_payloads  # idempotent on second call
