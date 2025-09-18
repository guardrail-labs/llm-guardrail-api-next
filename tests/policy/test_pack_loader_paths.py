from __future__ import annotations

from app.services.policy_packs import list_available_packs, resolve_pack_path


def test_resolve_pack_path_finds_in_both(tmp_path, monkeypatch):
    repo = tmp_path
    d1 = repo / "policies" / "packs"
    d2 = repo / "policy" / "packs"
    d1.mkdir(parents=True, exist_ok=True)
    d2.mkdir(parents=True, exist_ok=True)

    (d1 / "pii_redact.yaml").write_text("policy_version: v1\n", encoding="utf-8")
    (d2 / "secrets_redact.yaml").write_text("policy_version: v2\n", encoding="utf-8")

    monkeypatch.chdir(repo)

    p1 = resolve_pack_path("pii_redact")
    p2 = resolve_pack_path("secrets_redact")
    assert p1 is not None and p1.name == "pii_redact.yaml"
    assert p2 is not None and p2.name == "secrets_redact.yaml"

    names = {name for name, _ in list_available_packs()}
    assert "pii_redact" in names
    assert "secrets_redact" in names


def test_precedence_prefers_policies_packs(tmp_path, monkeypatch):
    repo = tmp_path
    d1 = repo / "policies" / "packs"
    d2 = repo / "policy" / "packs"
    d1.mkdir(parents=True, exist_ok=True)
    d2.mkdir(parents=True, exist_ok=True)

    (d1 / "dup.yaml").write_text("policy_version: from_policies\n", encoding="utf-8")
    (d2 / "dup.yaml").write_text("policy_version: from_policy\n", encoding="utf-8")

    monkeypatch.chdir(repo)

    p = resolve_pack_path("dup")
    assert p is not None and "policies/packs" in str(p).replace("\\", "/")
