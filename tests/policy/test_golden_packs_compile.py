from pathlib import Path

from app.services.policy_validate import validate_yaml_text


def _load(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_pii_pack_parses_and_compiles() -> None:
    txt = _load("policy/packs/pii_redact.yaml")
    res = validate_yaml_text(txt)
    assert res["status"] == "ok", res


def test_secrets_pack_parses_and_compiles() -> None:
    txt = _load("policy/packs/secrets_redact.yaml")
    res = validate_yaml_text(txt)
    assert res["status"] == "ok", res
