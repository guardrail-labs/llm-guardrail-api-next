from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient

import app.config as cfg
import app.main as main
from app.services.escalation import reset_memory


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
    assert r.headers.get("X-Guardrail-Decision") in (
        "clarify",
        "block",
    )  # helper sets clarify decision


def test_rulepack_ingress_block(client, monkeypatch):
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    monkeypatch.setenv("RULEPACKS_INGRESS_MODE", "block")

    r = _post_eval(client, "DROP TABLE sales;")
    assert r.status_code == 200
    j = r.json()
    assert j["action"] == "block_input_only"
    assert r.headers.get("X-Guardrail-Ingress-Action") == "block_input_only"


def test_escalation_execute_locked(client, monkeypatch):
    reset_memory()
    # enable escalation with low thresholds for test
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    monkeypatch.setenv("RULEPACKS_INGRESS_MODE", "clarify")
    monkeypatch.setenv("ESCALATION_ENABLED", "1")
    monkeypatch.setenv("ESCALATION_TIER1_THRESHOLD", "2")  # 2 unsafe -> execute_locked
    monkeypatch.setenv("ESCALATION_TIER2_THRESHOLD", "99")  # don't hit
    headers = {"X-API-Key": "test", "User-Agent": "pytest"}

    _post_eval(client, "DROP TABLE a;", headers=headers)
    r = _post_eval(client, "DROP TABLE b;", headers=headers)
    assert r.status_code == 200
    j = r.json()
    # Either clarify (tier not yet reached) or execute_locked right at threshold
    assert j.get("action") in ("clarify", "execute_locked")

    # One more to ensure execute_locked
    r2 = _post_eval(client, "DROP TABLE c;", headers=headers)
    assert r2.status_code == 200
    j2 = r2.json()
    assert j2.get("action") == "execute_locked"
    assert r2.headers.get("X-Guardrail-Ingress-Action") == "execute_locked"


def test_escalation_full_quarantine(client, monkeypatch):
    reset_memory()
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    monkeypatch.setenv("RULEPACKS_INGRESS_MODE", "clarify")
    monkeypatch.setenv("ESCALATION_ENABLED", "1")
    monkeypatch.setenv("ESCALATION_TIER1_THRESHOLD", "1")
    monkeypatch.setenv("ESCALATION_TIER2_THRESHOLD", "2")
    monkeypatch.setenv("ESCALATION_QUARANTINE_HTTP", "429")
    monkeypatch.setenv("ESCALATION_RETRY_AFTER_SEC", "5")
    headers = {"X-API-Key": "fq", "User-Agent": "pytest"}

    _post_eval(client, "DROP TABLE x;", headers=headers)  # unsafe 1
    _post_eval(client, "DROP TABLE y;", headers=headers)  # unsafe 2 -> tier2
    r = _post_eval(client, "DROP TABLE z;", headers=headers)  # should be quarantined
    assert r.status_code == 429
    assert r.headers.get("Retry-After") == "5"
    j = r.json()
    assert j.get("action") == "full_quarantine"
