from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient


def _mk_app():
    app = FastAPI()
    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    big = "A" * (2 * 1024 * 1024)

    @app.get("/big")
    def big_resp():
        return PlainTextResponse(big)

    return app


def test_skip_on_oversize(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_MAX_BYTES", "1048576")
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    client = TestClient(_mk_app())
    response = client.get("/big")
    assert response.status_code == 200
    assert response.headers.get("X-Redaction-Skipped") == "oversize"
