from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    def _factory() -> Any:
        return create_app()

    return _factory


def test_version_endpoint_basic(app_factory, monkeypatch):
    monkeypatch.setenv("APP_VERSION", "1.2.3")
    monkeypatch.setenv("GIT_SHA", "abc1234")
    monkeypatch.setenv("BUILD_TS", "2025-09-20T12:00:00Z")
    client = TestClient(app_factory())

    response = client.get("/version")
    assert response.status_code == 200

    payload = response.json()
    assert payload["version"] == "1.2.3"
    assert payload["git_sha"] == "abc1234"
    assert payload["build_ts"] == "2025-09-20T12:00:00Z"
    assert isinstance(payload.get("features"), dict)

    from app.services import ratelimit as ratelimit_service

    monkeypatch.setattr(ratelimit_service, "_global_enabled", None, raising=False)
    monkeypatch.setattr(ratelimit_service, "_global_limiter", None, raising=False)
