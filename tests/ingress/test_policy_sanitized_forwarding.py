from __future__ import annotations

from typing import Any, Dict


async def _capture_payload(ctx: Dict[str, Any], captured: Dict[str, Any]) -> Dict[str, Any]:
    captured["payload"] = ctx.get("payload")
    return {"text": "ok"}


def test_policy_sanitized_text_is_forwarded(client, monkeypatch):
    payload = {"text": "orig\x00text"}
    captured: Dict[str, Any] = {}

    async def _wrapper(ctx):
        return await _capture_payload(ctx, captured)

    monkeypatch.setattr("app.runtime.router._call_model", _wrapper)

    resp = client.post("/chat/completions", json=payload)

    assert resp.status_code == 200
    assert isinstance(captured.get("payload"), dict)
    assert captured["payload"].get("text") != "orig\x00text"
