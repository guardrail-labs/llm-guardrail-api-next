from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_threat_feed_dynamic_redaction_policy():
    # Enable the feature and point to a dummy URL (won't be fetched due to monkeypatch)
    os.environ["THREAT_FEED_ENABLED"] = "true"
    os.environ["THREAT_FEED_URLS"] = "https://example.local/feed"

    # Monkeypatch the fetcher to return a local spec
    from app.services import threat_feed as tf

    def _fake_fetch_json(_url: str):
        return {
            "version": "test",
            "redactions": [
                {
                    "pattern": r"token_[0-9]{6}",
                    "tag": "secrets:vendor_token",
                    "replacement": "[REDACTED:VENDOR_TOKEN]",
                }
            ],
        }

    tf._fetch_json = _fake_fetch_json

    # Trigger refresh
    r_reload = client.post("/admin/threat/reload")
    assert r_reload.status_code == 200
    body_reload = r_reload.json()
    assert body_reload["ok"] is True
    assert body_reload["result"]["compiled"] == 1

    # Now the pattern should redact during ingress evaluate
    txt = "here is token_123456 for you"
    r_eval = client.post("/guardrail/evaluate", json={"text": txt})
    assert r_eval.status_code == 200
    out = r_eval.json()

    # Contract: allow when only redactions happen
    assert out["action"] == "allow"
    assert "[REDACTED:VENDOR_TOKEN]" in out["text"]
    assert "secrets:*" in (out.get("rule_hits") or [])
