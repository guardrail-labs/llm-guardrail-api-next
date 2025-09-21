from __future__ import annotations

from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    def _factory() -> Any:
        return create_app()

    return _factory


def test_healthz_ok(app_factory: Callable[[], Any]) -> None:
    client = TestClient(app_factory())
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["status"] == "ok"


def test_readyz_file_checks_ok(
    app_factory: Callable[[], Any], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("AUDIT_BACKEND", "file")
    monkeypatch.setenv("AUDIT_LOG_FILE", str(tmp_path / "audit.ndjson"))
    monkeypatch.setenv("MITIGATION_STORE_BACKEND", "file")
    monkeypatch.setenv("MITIGATION_STORE_FILE", str(tmp_path / "mitigation.json"))

    client = TestClient(app_factory())
    response = client.get("/readyz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    checks = payload["checks"]
    assert checks["audit_file"]["status"] == "ok"
    assert checks["audit_file"]["detail"]["writable"] is True
    assert checks["mitigation_file"]["status"] == "ok"
    assert checks["mitigation_file"]["detail"]["writable"] is True


def test_readyz_redis_missing_is_503_when_configured(
    app_factory: Callable[[], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6399/0")

    client = TestClient(app_factory())
    response = client.get("/readyz")
    assert response.status_code == 503
    payload = response.json()
    assert payload["ok"] is False
    assert payload["checks"]["redis"]["status"] == "fail"
