from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _write_rules(path: Path, version: str) -> str:
    """
    Minimal rules.yaml writer: sets a distinct version for assertion.
    """
    text = f'version: "{version}"\ndeny: []\n'
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_bindings_resolve_returns_rules_path_and_version(tmp_path: Path, monkeypatch) -> None:
    # Protect admin endpoints with a key (optional behavior).
    monkeypatch.setenv("ADMIN_API_KEY", "secret")
    admin_h = {"X-Admin-Key": "secret"}

    # Create a distinct rules file and bind it to (tenant, bot).
    rules_a = _write_rules(tmp_path / "rules-a.yaml", "A")

    r = client.put(
        "/admin/bindings",
        headers=admin_h,
        json={
            "bindings": [
                {"tenant": "acme", "bot": "bot-a", "rules_path": rules_a},
            ]
        },
    )
    assert r.status_code == 200, r.text

    # Introspect active binding.
    r2 = client.get(
        "/admin/bindings/resolve",
        headers=admin_h,
        params={"tenant": "acme", "bot": "bot-a"},
    )
    assert r2.status_code == 200, r2.text
    body: Dict[str, Any] = r2.json()

    assert body["tenant"] == "acme"
    assert body["bot"] == "bot-a"
    assert body["rules_path"] == rules_a
    assert body["policy_version"] == "A"
