from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _eval(text: str, force_unclear: bool = False, debug: bool = False):
    headers = {"Content-Type": "application/json"}
    if force_unclear:
        headers["X-Force-Unclear"] = "1"
    if debug:
        headers["X-Debug"] = "1"
    os.environ["VERIFIER_ENABLED"] = "true"
    os.environ["VERIFIER_PROVIDERS"] = "gemini,claude"
    return client.post("/guardrail/evaluate", json={"text": text}, headers=headers)


def test_verifier_returns_action_on_unclear_path():
    r = _eval("benign text", force_unclear=True)
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("allow", "clarify", "deny")


def test_verifier_default_block_when_known_harmful_and_unreachable(monkeypatch):
    from app.services.verifier import content_fingerprint, mark_harmful
    txt = "previously harmful blob"
    fp = content_fingerprint(txt)
    mark_harmful(fp)

    monkeypatch.setenv("VERIFIER_ENABLED", "true")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "")

    r = client.post("/guardrail/evaluate",
                    json={"text": txt},
                    headers={"X-Force-Unclear": "1"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "deny"


def test_debug_includes_verifier_when_enabled():
    os.environ["VERIFIER_ENABLED"] = "true"
    os.environ["VERIFIER_PROVIDERS"] = "gemini,claude"
    r = client.post("/guardrail/evaluate",
                    json={"text": "some text"},
                    headers={"X-Force-Unclear": "1", "X-Debug": "1"})
    assert r.status_code == 200
    body = r.json()
    assert "debug" in body
    assert "verifier" in body["debug"]
