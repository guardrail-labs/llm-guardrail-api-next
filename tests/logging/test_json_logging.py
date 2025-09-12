# tests/logging/test_json_logging.py
# Summary (PR-M): Validates config snapshot and per-request JSON access log.

from __future__ import annotations

import importlib
import json
import logging
import os

from fastapi.testclient import TestClient


def _client_with_env(env: dict[str, str]) -> TestClient:
    for k, v in env.items():
        os.environ[k] = v
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def _find_json_event(caplog, event: str) -> dict | None:
    for rec in caplog.records:
        try:
            obj = json.loads(rec.getMessage())
            if isinstance(obj, dict) and obj.get("event") == event:
                return obj
        except Exception:
            continue
    return None


def test_logs_config_snapshot_and_access(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="guardrail"):
        client = _client_with_env(
            {
                "LOG_JSON_ENABLED": "1",
                "LOG_REQUESTS_ENABLED": "1",
                "LOG_REQUESTS_PATHS": "/health,/admin",
                "CORS_ALLOW_ORIGINS": "http://example.com",
                "MAX_REQUEST_BYTES": "12345",
            }
        )
        # Trigger a simple request
        r = client.get("/health", headers={"Origin": "http://example.com"})
        assert r.status_code in (200, 401, 302, 307)

    snap = _find_json_event(caplog, "config_snapshot")
    assert snap is not None
    assert "max_request_bytes" in snap
    assert "cors_allow_origins" in snap

    access = _find_json_event(caplog, "http_access")
    assert access is not None
    assert access.get("method") == "GET"
    assert access.get("path") == "/health"
    assert isinstance(access.get("duration_ms"), int)

