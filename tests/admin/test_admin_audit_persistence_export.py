from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app import config as app_config
from app.observability import admin_audit as audit_log


def _seed_events() -> None:
    audit_log.record(
        action="mitigation_set",
        actor_email="a@x",
        actor_role="admin",
        tenant="t",
        bot="b",
        outcome="ok",
        meta={"mode": "block"},
    )
    audit_log.record(
        action="dlq_purge",
        actor_email="o@x",
        actor_role="operator",
        outcome="ok",
        meta={"deleted": 1},
    )
    audit_log.record(
        action="retention_execute",
        actor_email="o@x",
        actor_role="operator",
        tenant="t",
        bot="b",
        outcome="error",
        meta={"before_ts_ms": 1},
    )


class _StubPipeline:
    def __init__(self, client: "_StubRedis") -> None:
        self._client = client
        self._commands: List[tuple[str, tuple[Any, ...]]] = []

    def rpush(self, key: str, value: str) -> "_StubPipeline":
        self._commands.append(("rpush", (key, value)))
        return self

    def ltrim(self, key: str, start: int, end: int) -> "_StubPipeline":
        self._commands.append(("ltrim", (key, start, end)))
        return self

    def execute(self) -> List[Any]:
        for name, args in self._commands:
            if name == "rpush":
                self._client._apply_rpush(*args)
            elif name == "ltrim":
                self._client._apply_ltrim(*args)
        self._commands.clear()
        return []


class _StubRedis:
    def __init__(self) -> None:
        self.values: Dict[str, List[str]] = {}

    def pipeline(self) -> _StubPipeline:
        return _StubPipeline(self)

    def _apply_rpush(self, key: str, value: str) -> None:
        bucket = self.values.setdefault(key, [])
        bucket.append(value)

    def _apply_ltrim(self, key: str, start: int, end: int) -> None:
        bucket = self.values.setdefault(key, [])
        length = len(bucket)
        if length == 0:
            return
        if start < 0:
            start = max(length + start, 0)
        if end < 0:
            end = length + end
        start = max(start, 0)
        end = min(end, length - 1)
        if start > end:
            self.values[key] = []
            return
        self.values[key] = bucket[start : end + 1]

    def lrange(self, key: str, start: int, end: int) -> List[str]:
        bucket = self.values.get(key, [])
        length = len(bucket)
        if length == 0:
            return []
        if start < 0:
            start = max(length + start, 0)
        if end < 0:
            end = length + end
        start = max(start, 0)
        end = min(end, length - 1)
        if start > end:
            return []
        return list(bucket[start : end + 1])


@pytest.fixture(autouse=True)
def _reset_audit_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_config, "AUDIT_BACKEND", "", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_LOG_FILE", "", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_REDIS_MAXLEN", 50000, raising=False)
    monkeypatch.setattr(app_config, "AUDIT_RECENT_LIMIT", 500, raising=False)
    monkeypatch.setattr(audit_log, "_REDIS_CLIENT", None, raising=False)
    monkeypatch.setattr(audit_log, "_REDIS_URL", None, raising=False)
    with audit_log._LOG_LOCK:
        audit_log._RING.clear()
    yield
    with audit_log._LOG_LOCK:
        audit_log._RING.clear()


@pytest.fixture()
def app_factory():
    from app.main import create_app
    from app.security import rbac as rbac_mod

    def _factory():
        app = create_app()

        def _allow(_: Optional[Request] = None) -> Dict[str, Any]:
            return {"email": "admin@example.com", "role": "admin"}

        app.dependency_overrides[rbac_mod.require_viewer] = _allow
        return app

    return _factory


def test_file_backend_round_trip(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.ndjson")
        monkeypatch.setattr(app_config, "AUDIT_BACKEND", "file", raising=False)
        monkeypatch.setattr(app_config, "AUDIT_LOG_FILE", path, raising=False)

        _seed_events()

        entries = audit_log.recent(10)
        assert any(item["action"] == "mitigation_set" for item in entries)
        assert any(item["action"] == "retention_execute" for item in entries)
        with open(path, "r", encoding="utf-8") as handle:
            lines = [ln.strip() for ln in handle.readlines() if ln.strip()]
        assert len(lines) == len(entries)


def test_redis_backend_round_trip(monkeypatch: pytest.MonkeyPatch):
    stub = _StubRedis()
    monkeypatch.setattr(app_config, "AUDIT_BACKEND", "redis", raising=False)
    monkeypatch.setattr(audit_log, "_redis_client", lambda: stub)

    _seed_events()

    with audit_log._LOG_LOCK:
        audit_log._RING.clear()

    entries = audit_log.recent(5)
    stored = stub.values.get(app_config.AUDIT_REDIS_KEY)
    assert stored is not None and stored
    assert any(item["action"] == "dlq_purge" for item in entries)


def test_export_with_filters(app_factory, monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.ndjson")
        monkeypatch.setattr(app_config, "AUDIT_BACKEND", "file", raising=False)
        monkeypatch.setattr(app_config, "AUDIT_LOG_FILE", path, raising=False)

        app = app_factory()
        _seed_events()

        client = TestClient(app)
        response = client.get("/admin/api/audit/export.ndjson?tenant=t&bot=b")

        assert response.status_code == 200
        body = [json.loads(line) for line in response.text.splitlines() if line.strip()]
        assert any(item["action"] == "mitigation_set" for item in body)
        assert any(item["action"] == "retention_execute" for item in body)


def test_memory_fallback_export(app_factory, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_config, "AUDIT_BACKEND", "memory", raising=False)
    monkeypatch.setattr(app_config, "AUDIT_LOG_FILE", "", raising=False)

    app = app_factory()
    _seed_events()

    client = TestClient(app)
    response = client.get("/admin/api/audit/export.ndjson?action=dlq_purge")

    assert response.status_code == 200
    lines = response.text.splitlines()
    assert any('"action":"dlq_purge"' in line for line in lines)
