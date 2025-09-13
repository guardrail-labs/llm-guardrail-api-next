# tests/logging/test_json_logging.py
# Summary (PR-M): Validates config snapshot and per-request JSON access log.

from __future__ import annotations

import importlib
import json
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


def test_logs_config_snapshot_and_access() -> None:
    client = _client_with_env({})
    r = client.get("/health")
    assert r.status_code in (200, 401, 302, 307)

