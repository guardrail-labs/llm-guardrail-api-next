from __future__ import annotations

import app.services.policy as pol


def _set_packs(monkeypatch, names):
    monkeypatch.setattr("app.services.policy.get_policy_packs", lambda: list(names))


def test_version_changes_with_order(monkeypatch):
    _set_packs(monkeypatch, ["base", "hipaa"])
    v1 = pol.force_reload()
    assert isinstance(v1, str) and len(v1) == 64

    _set_packs(monkeypatch, ["hipaa", "base"])
    v2 = pol.force_reload()
    assert isinstance(v2, str) and len(v2) == 64
    assert v1 != v2  # order affects merge/version


def test_effective_setting_reflects_order(monkeypatch):
    _set_packs(monkeypatch, ["base", "hipaa"])
    pol.force_reload()
    assert pol._RULES["settings"]["egress"]["redact_enabled"] is True

    _set_packs(monkeypatch, ["hipaa", "base"])
    pol.force_reload()
    assert pol._RULES["settings"]["egress"]["redact_enabled"] is False
