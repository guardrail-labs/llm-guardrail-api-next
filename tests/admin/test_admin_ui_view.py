from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_admin_ui_serves_html(client: TestClient) -> None:
    r = client.get("/admin/ui")
    assert r.status_code == 200
    # Very light assertion: contains title and fetch path
    text = r.text
    assert "Guardrail Admin — Active Policy" in text
    assert "/admin/policies/active" in text
