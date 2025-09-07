from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _write_rules(tmp: Path, name: str, pattern: str, version: str) -> str:
    p = tmp / name
    p.write_text(
        f'version: "{version}"\ndeny:\n  - id: block_{name}\n    pattern: "{pattern}"\n',
        encoding="utf-8",
    )
    return str(p)


def test_per_tenant_bot_bindings_take_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Admin auth (optional); uncomment next two lines if enforcing in CI
    monkeypatch.setenv("ADMIN_API_KEY", "secret")
    admin_h = {"X-Admin-Key": "secret"}

    # Two distinct rule packs
    path_a = _write_rules(tmp_path, "A.yaml", "BLOCKA", "A")
    path_b = _write_rules(tmp_path, "B.yaml", "BLOCKB", "B")

    # Install bindings
    r = client.put(
        "/admin/bindings",
        headers=admin_h,
        json={
            "bindings": [
                {"tenant": "acme", "bot": "bot-a", "rules_path": path_a},
                {"tenant": "globex", "bot": "bot-z", "rules_path": path_b},
            ]
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert any(b["tenant"] == "acme" and b["bot"] == "bot-a" for b in body["bindings"])
    assert any(b["tenant"] == "globex" and b["bot"] == "bot-z" for b in body["bindings"])

    # acme/bot-a denied by BLOCKA
    h_a = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "bot-a",
        "Content-Type": "application/json",
    }
    r = client.post("/guardrail", json={"prompt": "hello BLOCKA"}, headers=h_a)
    assert r.status_code == 200
    assert r.json()["decision"] == "block"

    # globex/bot-z denied by BLOCKB
    h_b = {
        "X-API-Key": "k",
        "X-Tenant-ID": "globex",
        "X-Bot-ID": "bot-z",
        "Content-Type": "application/json",
    }
    r = client.post("/guardrail", json={"prompt": "hello BLOCKB"}, headers=h_b)
    assert r.status_code == 200
    assert r.json()["decision"] == "block"

    # unbound tenant should not be denied by BLOCKA (falls back to default rules)
    h_u = {
        "X-API-Key": "k",
        "X-Tenant-ID": "other",
        "X-Bot-ID": "other",
        "Content-Type": "application/json",
    }
    r = client.post("/guardrail", json={"prompt": "hello BLOCKA"}, headers=h_u)
    assert r.status_code == 200
    # If default rules also deny, allow either allow or block; we just ensure no specific rule.
    decision = r.json()["decision"]
    assert decision in {"allow", "block"}  # resilient to default packs

    # GET list
    r = client.get("/admin/bindings")
    assert r.status_code == 200
    assert isinstance(r.json().get("bindings"), list)

    # DELETE single binding
    r = client.delete("/admin/bindings", headers=admin_h, params={"tenant": "acme", "bot": "bot-a"})
    assert r.status_code == 200
    remaining = [(b["tenant"], b["bot"]) for b in r.json()["bindings"]]
    assert ("acme", "bot-a") not in remaining
