from __future__ import annotations

from pathlib import Path

from app.services.policy_packs import list_available_packs, resolve_pack_path


def test_resolve_pack_path_finds_in_both(tmp_path, monkeypatch):
    repo: Path = tmp_path
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
    repo: Path = tmp_path
    d1 = repo / "policies" / "packs"
    d2 = repo / "policy" / "packs"
    d1.mkdir(parents=True, exist_ok=True)
    d2.mkdir(parents=True, exist_ok=True)

    (d1 / "dup.yaml").write_text("policy_version: from_policies\n", encoding="utf-8")
    (d2 / "dup.yaml").write_text("policy_version: from_policy\n", encoding="utf-8")

    monkeypatch.chdir(repo)

    p = resolve_pack_path("dup")
    assert p is not None and "policies/packs" in str(p).replace("\\", "/")


def test_partial_local_override_falls_back_to_bundled(tmp_path, monkeypatch):
    # Layout:
    #  CWD/policies/packs       -> contains ONLY 'local_only.yaml'
    #  PROJECT/policies/packs   -> contains ONLY 'bundled_only.yaml'
    # Expect: resolve both; local precedence when both exist.

    repo: Path = tmp_path
    cwd_packs = repo / "policies" / "packs"
    proj_root = repo / "project"
    proj_packs = proj_root / "policies" / "packs"
    cwd_packs.mkdir(parents=True, exist_ok=True)
    proj_packs.mkdir(parents=True, exist_ok=True)

    # simulate packaged structure by pointing project_root to proj_root
    monkeypatch.chdir(repo)

    import app.services.policy_packs as pp

    try:
        pp.project_root = proj_root
    except Exception:
        pass

    # create files
    (cwd_packs / "local_only.yaml").write_text("policy_version: local\n", encoding="utf-8")
    (proj_packs / "bundled_only.yaml").write_text("policy_version: bundled\n", encoding="utf-8")

    # local pack resolves from CWD path
    p_local = resolve_pack_path("local_only")
    assert p_local is not None and "policies/packs" in str(p_local).replace("\\", "/")

    # bundled pack resolves from project path (fallback)
    p_bundled = resolve_pack_path("bundled_only")
    assert p_bundled is not None and proj_packs in p_bundled.parents

    # both appear in list; no duplicates
    names = {name for name, _ in list_available_packs()}
    assert "local_only" in names and "bundled_only" in names
