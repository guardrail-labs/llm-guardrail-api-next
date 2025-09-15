from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.abuse_gate import AbuseGateMiddleware
from app.services.abuse.engine import AbuseConfig


def _app(cfg: AbuseConfig) -> FastAPI:
    app = FastAPI()
    # Escalate quickly for deterministic tests:
    # 1 strike -> execute_locked (short cooldown)
    # 2 strikes -> full_quarantine (longer cooldown)
    app.add_middleware(
        AbuseGateMiddleware,
        cfg=cfg,
        enabled=True,
    )

    @app.get("/ok")
    def ok() -> PlainTextResponse:
        return PlainTextResponse("ok")

    return app


def test_execute_locked_then_full_quarantine(monkeypatch):
    cfg = AbuseConfig(
        strike_window_sec=60,
        tiers=[(1, "execute_locked", 30), (2, "full_quarantine", 120)],
    )
    app = _app(cfg)

    # Make the verdict hook return "unsafe"
    import app.middleware.abuse_gate as gate

    monkeypatch.setattr(gate, "fetch_verdict", lambda req: "unsafe")

    c = TestClient(app)

    # First request -> execute_locked (allowed 200 + headers)
    r1 = c.get("/ok", headers={"x-api-key": "keyA"})
    assert r1.status_code == 200
    assert r1.headers.get("X-Guardrail-Decision") in ("allow", "deny")
    assert r1.headers.get("X-Guardrail-Mode") in ("normal", "execute_locked")
    # Second unsafe request -> full_quarantine (429)
    r2 = c.get("/ok", headers={"x-api-key": "keyA"})
    assert r2.status_code == 429
    assert r2.json()["code"] == "guardrail_quarantined"
    assert r2.headers.get("X-Guardrail-Decision") == "deny"
    assert r2.headers.get("X-Guardrail-Mode") == "full_quarantine"
    assert "Retry-After" in r2.headers


def test_quarantine_short_circuits(monkeypatch):
    cfg = AbuseConfig(
        strike_window_sec=60,
        tiers=[(1, "execute_locked", 30), (2, "full_quarantine", 120)],
    )
    app = _app(cfg)

    import app.middleware.abuse_gate as gate

    # First two unsafe requests reach full quarantine
    monkeypatch.setattr(gate, "fetch_verdict", lambda req: "unsafe")
    c = TestClient(app)
    assert c.get("/ok", headers={"x-api-key": "keyB"}).status_code in (200, 429)
    assert c.get("/ok", headers={"x-api-key": "keyB"}).status_code == 429
    # Subsequent safe request should still be quarantined
    monkeypatch.setattr(gate, "fetch_verdict", lambda req: "safe")
    r2 = c.get("/ok", headers={"x-api-key": "keyB"})
    assert r2.status_code == 429
    assert r2.headers.get("X-Guardrail-Decision") == "deny"
    assert r2.headers.get("X-Guardrail-Mode") == "full_quarantine"
