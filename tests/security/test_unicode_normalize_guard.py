from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from app.middleware.unicode_normalize_guard import UnicodeNormalizeGuard


def create_app() -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(body: dict) -> JSONResponse:  # type: ignore[override]
        return JSONResponse(body)

    app.add_middleware(
        UnicodeNormalizeGuard,
        default_mode="normalize",
        norm_form="NFC",
        max_body_bytes=100_000,
    )
    return app


def test_normalizes_nfc_and_sets_headers() -> None:
    app = create_app()
    client = TestClient(app)
    response = client.post("/echo", json={"k": "e\u0301"})
    assert response.status_code == 200
    assert response.json()["k"] == "é"
    assert response.headers.get("x-confusables-norm-changed") == "1"


def test_block_mode_returns_400() -> None:
    app = FastAPI()

    @app.post("/x")
    async def route(body: dict) -> JSONResponse:  # type: ignore[override]
        return JSONResponse(body)

    app.add_middleware(UnicodeNormalizeGuard, default_mode="block", norm_form="NFC")
    client = TestClient(app)
    response = client.post("/x", json={"s": "Pаypal"})
    assert response.status_code == 400
    payload = response.json()
    assert payload["mixed_scripts"] is True
