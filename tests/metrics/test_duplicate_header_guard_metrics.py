from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import get_config, set_config


@pytest.fixture()
def make_app():
    def _factory():
        return create_app()

    return _factory


def _scrape(text: str, metric: str, selector: str) -> float:
    total = 0.0
    for line in text.splitlines():
        if line.startswith(metric) and selector in line:
            try:
                total += float(line.rsplit(" ", 1)[-1])
            except Exception:
                pass
    return total


def test_duplicate_name_bucketed_other(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_duplicate_header_guard_mode": "log",
                "ingress_duplicate_header_unique": ["x-request-id"],
                "ingress_duplicate_header_metric_allowlist": ["x-request-id"],
            },
            replace=True,
        )
        with TestClient(make_app()) as client:
            before = client.get("/metrics").text
            base = _scrape(
                before,
                "guardrail_ingress_duplicate_header_total",
                'name="_other"',
            )
            response = client.get(
                "/health",
                headers=[("X-Note", "a"), ("x-note", "b")],
            )
            assert response.status_code == 200
            after = client.get("/metrics").text
        updated = _scrape(
            after,
            "guardrail_ingress_duplicate_header_total",
            'name="_other"',
        )
        assert updated > base
    finally:
        set_config(initial, replace=True)


def test_duplicate_unique_uses_real_name(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_duplicate_header_guard_mode": "log",
                "ingress_duplicate_header_unique": ["x-request-id"],
                "ingress_duplicate_header_metric_allowlist": ["x-request-id"],
            },
            replace=True,
        )
        with TestClient(make_app()) as client:
            before = client.get("/metrics").text
            base = _scrape(
                before,
                "guardrail_ingress_duplicate_header_total",
                'name="x-request-id"',
            )
            response = client.get(
                "/health",
                headers=[("X-Request-ID", "a"), ("x-request-id", "b")],
            )
            assert response.status_code == 200
            after = client.get("/metrics").text
        updated = _scrape(
            after,
            "guardrail_ingress_duplicate_header_total",
            'name="x-request-id"',
        )
        assert updated > base
    finally:
        set_config(initial, replace=True)
