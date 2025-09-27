from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.observability.metrics import ingress_header_limit_blocked
from app.services.config_store import get_config, set_config


@pytest.fixture()
def make_app():
    def _factory():
        return create_app()

    return _factory


def _reason_total(reason: str) -> float:
    total = 0.0
    for metric in ingress_header_limit_blocked.collect():
        for sample in metric.samples:
            if sample.labels.get("reason") == reason:
                total += float(sample.value)
    return total


def test_metric_increments_on_count_block(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_header_limits_enabled": True,
                "ingress_max_header_count": 1,
                "ingress_max_header_value_bytes": 0,
            },
            replace=True,
        )
        baseline = _reason_total("count")
        with TestClient(make_app()) as client:
            response = client.get("/health", headers={"A": "1", "B": "2"})
            assert response.status_code == 431
            assert response.headers.get("X-Guardrail-Header-Limit-Blocked") == "count"
        updated = _reason_total("count")
        assert updated > baseline
    finally:
        set_config(initial, replace=True)


def test_metric_increments_on_value_len_block(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_header_limits_enabled": True,
                "ingress_max_header_count": 0,
                "ingress_max_header_value_bytes": 2,
            },
            replace=True,
        )
        baseline = _reason_total("value_len")
        with TestClient(make_app()) as client:
            response = client.get("/health", headers={"A": "123"})
            assert response.status_code == 431
            assert response.headers.get("X-Guardrail-Header-Limit-Blocked") == "value_len"
        updated = _reason_total("value_len")
        assert updated > baseline
    finally:
        set_config(initial, replace=True)
