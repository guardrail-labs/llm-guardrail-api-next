# tests/middleware/test_max_body.py
# Summary (PR-L): Validates 413 on oversized body and allows small payloads.

from __future__ import annotations

import importlib
import os

from fastapi.testclient import TestClient


def _client_with_env(env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        os.environ[k] = v
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_blocks_large_post_to_admin_apply() -> None:
    client = _client_with_env(
        {
            "MAX_REQUEST_BYTES": "50",
            "MAX_REQUEST_BYTES_PATHS": "/admin",
            # ensure route available; apply may still be disabled but middleware fires first
            "ADMIN_ENABLE_APPLY": "0",
        }
    )

    # Body larger than 50 bytes
    payload = {"x": "a" * 200}
    r = client.post("/admin/bindings/apply", json=payload)
    assert r.status_code == 413
    data = r.json()
    assert data["code"] == "payload_too_large"
    assert "too large" in data["detail"].lower()


def test_small_body_allowed_passes_through() -> None:
    client = _client_with_env(
        {
            "MAX_REQUEST_BYTES": "1000",
            "MAX_REQUEST_BYTES_PATHS": "/admin",
            "ADMIN_ENABLE_APPLY": "0",
        }
    )
    # Small body below the limit
    payload = {"x": "ok"}
    r = client.post("/admin/bindings/apply", json=payload)
    # We only assert NOT 413; route may 401/200/302 depending on env/other middlewares
    assert r.status_code != 413
