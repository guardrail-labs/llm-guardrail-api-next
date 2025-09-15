from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient

import app.config as cfg
import app.main as main


def _make_client() -> TestClient:
    os.environ["API_KEY"] = "unit-test-key"
    importlib.reload(cfg)
    importlib.reload(main)
    return TestClient(main.build_app())


@pytest.fixture
def client() -> TestClient:
    return _make_client()


def _post_eval(client, text: str, headers: dict | None = None):
    return client.post("/guardrail/evaluate", json={"text": text}, headers=headers or {})


def test_rulepack_ingress_clarify(client, monkeypatch):
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    monkeypatch.setenv("RULEPACKS_INGRESS_MODE", "clarify")

    r = _post_eval(client, "Please DROP TABLE users;")
    assert r.status_code in (422, 200)  # clarify helper defaults 422
    j = r.json()
    assert j.get("action") == "clarify" or j.get("action") == "clarify"  # tolerate unify
    assert r.headers.get("X-Guardrail-Decision") in ("allow", "deny")


def test_rulepack_ingress_block(client, monkeypatch):
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    monkeypatch.setenv("RULEPACKS_INGRESS_MODE", "block")

    r = _post_eval(client, "DROP TABLE sales;")
    assert r.status_code == 200
    j = r.json()
    assert j["action"] == "block_input_only"
    assert r.headers.get("X-Guardrail-Ingress-Action") == "block_input_only"
