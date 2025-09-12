# tests/middleware/test_compression.py
# Summary: Basic checks that gzip header appears only when enabled.

from __future__ import annotations

import importlib

from starlette.testclient import TestClient

import app.main as main


def _client(monkeypatch, env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    importlib.reload(main)
    return TestClient(main.app)


def test_gzip_header_when_enabled(monkeypatch) -> None:
    client = _client(
        monkeypatch,
        {"COMPRESSION_ENABLED": "1", "COMPRESSION_MIN_SIZE_BYTES": "1"},
    )
    r = client.get("/health", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    assert r.headers.get("content-encoding") == "gzip"


def test_no_gzip_when_disabled(monkeypatch) -> None:
    client = _client(monkeypatch, {"COMPRESSION_ENABLED": "0"})
    r = client.get("/health", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200
    assert r.headers.get("content-encoding") is None
