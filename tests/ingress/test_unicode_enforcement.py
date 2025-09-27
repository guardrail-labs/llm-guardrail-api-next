from __future__ import annotations

from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import get_config, set_config


def _make_client() -> TestClient:
    return TestClient(create_app())


def _cfg(mode: str) -> dict[str, object]:
    return {
        "ingress_unicode_sanitizer_enabled": True,
        "ingress_unicode_enforce_mode": mode,
        "ingress_unicode_enforce_flags": ["bidi", "zwc"],
    }


def test_off_mode_allows() -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("off"), replace=True)
        with _make_client() as client:
            response = client.get("/health", params={"q": "x\u202ey"})
        assert response.status_code == 200
        assert "X-Guardrail-Unicode-Blocked" not in response.headers
    finally:
        set_config(initial, replace=True)


def test_log_mode_audits_but_allows() -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("log"), replace=True)
        with _make_client() as client:
            response = client.get("/health", params={"q": "x\u202ey"})
        assert response.status_code == 200
        audit = response.headers.get("X-Guardrail-Unicode-Audit", "")
        assert "bidi" in audit
    finally:
        set_config(initial, replace=True)


def test_block_mode_returns_400() -> None:
    initial = dict(get_config())
    try:
        set_config(_cfg("block"), replace=True)
        with _make_client() as client:
            response = client.get("/health", headers=[(b"x-note", "A\u200bB".encode("utf-8"))])
        assert response.status_code == 400
        blocked = response.headers.get("X-Guardrail-Unicode-Blocked", "")
        assert "zwc" in blocked
    finally:
        set_config(initial, replace=True)
