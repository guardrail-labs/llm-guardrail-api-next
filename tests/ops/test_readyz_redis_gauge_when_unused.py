from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app_factory() -> Callable[[], Any]:
    def _factory() -> Any:
        return create_app()

    return _factory


def test_readyz_redis_gauge_is_one_when_unconfigured(
    app_factory: Callable[[], Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("AUDIT_BACKEND", "memory")
    monkeypatch.setenv("MITIGATION_STORE_BACKEND", "memory")

    client = TestClient(app_factory())
    response = client.get("/readyz")
    assert response.status_code == 200

    metrics_text = client.get("/metrics").text
    line = next(
        (
            ln
            for ln in metrics_text.splitlines()
            if ln.startswith("guardrail_readyz_redis_ok")
        ),
        "guardrail_readyz_redis_ok 0",
    )
    parts = line.split()
    assert len(parts) >= 2, line
    assert float(parts[-1]) == pytest.approx(1.0), line
