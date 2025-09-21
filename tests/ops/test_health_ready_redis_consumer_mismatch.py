from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    def _factory() -> Any:
        return create_app()

    return _factory


def _stub_ping(ok: bool):
    class Stub:
        def ping(self):
            return ok

    return Stub()


def test_readyz_fails_when_one_configured_consumer_is_down(app_factory, monkeypatch):
    """Ensure readiness fails if a configured consumer cannot ping redis."""

    # Configure both consumers to use redis
    monkeypatch.setenv("AUDIT_BACKEND", "redis")
    monkeypatch.setenv("MITIGATION_STORE_BACKEND", "redis")
    # No global REDIS_URL needed

    # Make audit redis OK, mitigation redis fail
    from app.observability import admin_audit as AA
    from app.services import mitigation_store as MS

    monkeypatch.setattr(AA, "_redis_client", lambda: _stub_ping(True), raising=True)
    monkeypatch.setattr(MS, "_redis_client", lambda: _stub_ping(False), raising=True)

    c = TestClient(app_factory())
    r = c.get("/readyz")
    assert r.status_code == 503
    detail = r.json()["checks"]["redis"]["detail"]
    assert detail["configured"] is True
    assert "audit" in detail["used_by"] and "mitigation" in detail["used_by"]
    assert "mitigation" in detail["failed"] and detail["ok_all"] is False


def test_readyz_ok_when_all_configured_consumers_are_up(app_factory, monkeypatch):
    monkeypatch.setenv("AUDIT_BACKEND", "redis")
    monkeypatch.setenv("MITIGATION_STORE_BACKEND", "redis")

    from app.observability import admin_audit as AA
    from app.services import mitigation_store as MS

    monkeypatch.setattr(AA, "_redis_client", lambda: _stub_ping(True), raising=True)
    monkeypatch.setattr(MS, "_redis_client", lambda: _stub_ping(True), raising=True)

    c = TestClient(app_factory())
    r = c.get("/readyz")
    assert r.status_code == 200
    detail = r.json()["checks"]["redis"]["detail"]
    assert detail["ok_all"] is True
    assert detail["failed"] == []
