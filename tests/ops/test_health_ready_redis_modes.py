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


def test_readyz_flags_redis_when_audit_backend_is_redis_without_env(
    app_factory: Callable[[], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("MITIGATION_STORE_BACKEND", raising=False)
    monkeypatch.delenv("MITIGATION_STORE_FILE", raising=False)
    monkeypatch.setenv("AUDIT_BACKEND", "redis")
    c = TestClient(app_factory())
    r = c.get("/readyz")
    assert r.status_code == 503
    j = r.json()
    detail = j["checks"]["redis"]["detail"]
    assert detail["configured"] is True
    assert "audit" in detail["used_by"]
