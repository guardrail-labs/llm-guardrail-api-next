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


def _client(make_app) -> TestClient:
    return TestClient(make_app())


def _cfg(mode: str) -> dict[str, object]:
    return {
        "ingress_duplicate_header_guard_mode": mode,
        "ingress_duplicate_header_unique": [
            "content-length",
            "x-request-id",
            "traceparent",
        ],
    }


def test_off_mode_allows_duplicates(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("off"), replace=True)
        with _client(make_app) as client:
            response = client.get(
                "/health",
                headers=[("X-Note", "1"), ("x-note", "2")],
            )
        assert response.status_code == 200
        assert "X-Guardrail-Duplicate-Header-Audit" not in response.headers
    finally:
        set_config(initial, replace=True)


def test_log_mode_audits_duplicates(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("log"), replace=True)
        with _client(make_app) as client:
            response = client.get(
                "/health",
                headers=[("X-Note", "1"), ("x-note", "2")],
            )
        assert response.status_code == 200
        audit = response.headers.get("X-Guardrail-Duplicate-Header-Audit", "")
        assert "x-note" in audit.lower()
    finally:
        set_config(initial, replace=True)


def test_block_mode_blocks_unique_dups(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("block"), replace=True)
        with _client(make_app) as client:
            response = client.get(
                "/health",
                headers=[("X-Request-ID", "a"), ("x-request-id", "b")],
            )
        assert response.status_code == 400
        blocked = response.headers.get("X-Guardrail-Duplicate-Header-Blocked", "")
        assert "x-request-id" in blocked.lower()
    finally:
        set_config(initial, replace=True)
