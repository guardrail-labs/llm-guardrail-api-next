from __future__ import annotations

import importlib
import importlib.util

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ApiKeySpec = importlib.util.find_spec("app.middleware.api_key_auth")
API_KEY_MIDDLEWARE_PRESENT = ApiKeySpec is not None


@pytest.mark.skipif(not API_KEY_MIDDLEWARE_PRESENT, reason="API key middleware not present")
def test_probes_bypass_api_key() -> None:
    api_mod = importlib.import_module("app.middleware.api_key_auth")

    app = FastAPI()

    from app.routes.health import router as health_router

    app.include_router(health_router)
    app.add_middleware(getattr(api_mod, "APIKeyAuthMiddleware"))

    client = TestClient(app)

    assert client.get("/livez").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)
