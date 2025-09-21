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


def test_openapi_has_ops_and_decisions_tags(app_factory: Callable[[], Any]) -> None:
    client = TestClient(app_factory())
    document = client.get("/openapi.json").json()

    tags = {tag.get("name") for tag in document.get("tags", []) if isinstance(tag, dict)}
    assert "ops" in tags

    decisions_path = document.get("paths", {}).get("/admin/api/decisions", {})
    decisions_get = decisions_path.get("get", {}) if isinstance(decisions_path, dict) else {}
    assert decisions_get.get("summary") == "List decisions (cursor)"
    assert "admin-decisions" in decisions_get.get("tags", [])
