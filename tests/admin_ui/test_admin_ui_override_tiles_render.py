from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability.metrics import mitigation_override_counter
from app.routes import admin_mitigation


@pytest.fixture()
def app_factory():
    def _factory():
        app = create_app()

        def _allow(_: Request) -> None:
            return None

        app.dependency_overrides[admin_mitigation.require_admin_session] = _allow
        return app

    return _factory


def test_override_tiles_numbers_available(app_factory):
    """Override metrics endpoint returns seeded totals."""

    mitigation_override_counter.labels(mode="block").inc(3)
    mitigation_override_counter.labels(mode="clarify").inc(2)
    mitigation_override_counter.labels(mode="redact").inc(1)

    client = TestClient(app_factory())
    response = client.get("/admin/api/metrics/mitigation-overrides")
    assert response.status_code == 200

    totals = response.json()["totals"]
    assert totals["block"] >= 3
    assert totals["clarify"] >= 2
    assert totals["redact"] >= 1
