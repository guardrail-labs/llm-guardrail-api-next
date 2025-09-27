from __future__ import annotations

from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import get_config, set_config


def _client() -> TestClient:
    return TestClient(create_app())


def test_limits_disabled_allows() -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_header_limits_enabled": False,
                "ingress_max_header_count": 2,
                "ingress_max_header_value_bytes": 4,
            },
            replace=True,
        )
        with _client() as client:
            response = client.get(
                "/health",
                headers={"A": "aaaaa", "B": "bbbbb", "C": "cc"},
            )
        assert response.status_code == 200
    finally:
        set_config(initial, replace=True)


def test_blocks_on_count() -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_header_limits_enabled": True,
                "ingress_max_header_count": 2,
                "ingress_max_header_value_bytes": 0,
            },
            replace=True,
        )
        with _client() as client:
            response = client.get(
                "/health",
                headers={"A": "1", "B": "2", "C": "3"},
            )
        assert response.status_code == 431
        assert "too many headers" in response.text.lower()
        assert response.headers.get("Connection") == "close"
    finally:
        set_config(initial, replace=True)


def test_blocks_on_value_len() -> None:
    initial = dict(get_config())
    try:
        set_config(
            {
                "ingress_header_limits_enabled": True,
                "ingress_max_header_count": 0,
                "ingress_max_header_value_bytes": 4,
            },
            replace=True,
        )
        with _client() as client:
            response = client.get("/health", headers={"A": "12345"})
        assert response.status_code == 431
        assert "value too large" in response.text.lower()
        assert response.headers.get("Connection") == "close"
    finally:
        set_config(initial, replace=True)
