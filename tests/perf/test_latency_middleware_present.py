from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.latency_instrument import LatencyMiddleware


def test_latency_middleware_runs() -> None:
    app = FastAPI()
    app.add_middleware(LatencyMiddleware)

    @app.get("/x")
    async def x() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/x")
    assert response.status_code == 200
