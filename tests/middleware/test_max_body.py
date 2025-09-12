# tests/middleware/test_max_body.py
# Summary: Ensures 413 is returned for bodies exceeding MAX_REQUEST_BYTES.

from __future__ import annotations

from importlib import reload

from starlette.testclient import TestClient

import app.main as main


def test_over_limit_returns_413(monkeypatch) -> None:
    # 64-byte limit; send 128 bytes to a simple path
    monkeypatch.setenv("MAX_REQUEST_BYTES", "64")
    reload(main)
    client = TestClient(main.app)
    r = client.post("/health", content="x" * 128)
    assert r.status_code == 413
    data = r.json()
    assert data.get("code") == "payload_too_large"


def test_under_limit_passes_through(monkeypatch) -> None:
    monkeypatch.setenv("MAX_REQUEST_BYTES", "64")
    reload(main)
    client = TestClient(main.app)
    # This path is GET-only; posting will be 405 if it reaches routing,
    # which proves we didn't stop it with 413.
    r = client.post("/health", content="ok")
    assert r.status_code != 413
