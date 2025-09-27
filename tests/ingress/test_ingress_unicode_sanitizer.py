from __future__ import annotations

import pytest
from fastapi import Request
from starlette.testclient import TestClient

from app.main import create_app
from app.services.config_store import get_config, set_config


@pytest.fixture()
def make_app():
    def _factory():
        app = create_app()

        async def _state_payload(request: Request) -> dict[str, object]:
            data = getattr(request.state, "unicode", {})
            if isinstance(data, dict):
                flags = sorted(str(flag) for flag in data.get("flags", set()))
                return {
                    "flags": flags,
                    "normalized": str(data.get("normalized", "")),
                    "skeleton": str(data.get("skeleton", "")),
                }
            return {"flags": [], "normalized": "", "skeleton": ""}

        @app.get("/unicode-state")
        async def unicode_state(request: Request) -> dict[str, object]:
            return await _state_payload(request)

        @app.get("/unicode-state/{tail:path}")
        async def unicode_state_tail(tail: str, request: Request) -> dict[str, object]:
            return await _state_payload(request)

        return app

    return _factory


def _enable() -> dict[str, object]:
    return {
        "ingress_unicode_sanitizer_enabled": True,
        "ingress_unicode_header_sample_bytes": 4096,
        "ingress_unicode_query_sample_bytes": 4096,
        "ingress_unicode_path_sample_chars": 1024,
    }


def _client(factory) -> TestClient:
    return TestClient(factory())


def test_detects_zero_width_in_header(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_enable(), replace=True)
        with _client(make_app) as client:
            response = client.get(
                "/unicode-state",
                headers=[(b"x-note", "A\u200bB".encode("utf-8"))],
            )
        assert response.status_code == 200
        flags_header = response.headers.get("X-Guardrail-Ingress-Flags", "")
        assert "zwc" in flags_header.split(",")
        body = response.json()
        assert "zwc" in body["flags"]
    finally:
        set_config(initial, replace=True)


def test_detects_bidi_control_in_query(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_enable(), replace=True)
        bidi = "\u202e"
        with _client(make_app) as client:
            response = client.get("/unicode-state", params={"q": f"x{bidi}y"})
        assert response.status_code == 200
        flags_header = response.headers.get("X-Guardrail-Ingress-Flags", "")
        assert "bidi" in flags_header.split(",")
        body = response.json()
        assert "bidi" in body["flags"]
    finally:
        set_config(initial, replace=True)


def test_detects_confusables_and_mixed(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_enable(), replace=True)
        phishy = "p\u0430ypal"
        with _client(make_app) as client:
            response = client.get(
                "/unicode-state",
                headers=[(b"x-note", phishy.encode("utf-8"))],
            )
        assert response.status_code == 200
        flags_header = response.headers.get("X-Guardrail-Ingress-Flags", "")
        assert flags_header == "confusables,mixed"
        body = response.json()
        assert body["flags"] == ["confusables", "mixed"]
        assert body["normalized"]
        assert body["skeleton"]
    finally:
        set_config(initial, replace=True)


def test_detects_emoji_in_path(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_enable(), replace=True)
        emoji_path = "/unicode-state/status/ok\U0001f600"
        with _client(make_app) as client:
            response = client.get(emoji_path)
        assert response.status_code == 200
        flags_header = response.headers.get("X-Guardrail-Ingress-Flags", "")
        assert "emoji" in flags_header.split(",")
        body = response.json()
        assert "emoji" in body["flags"]
    finally:
        set_config(initial, replace=True)


def test_confusables_detected_before_normalization(make_app) -> None:
    initial = dict(get_config())
    try:
        set_config(_enable(), replace=True)
        confusable_path = "/unicode-state/state/\uff21\uff22\uff23"
        with _client(make_app) as client:
            response = client.get(confusable_path)
        assert response.status_code in (200, 404)
        flags_header = response.headers.get("X-Guardrail-Ingress-Flags", "")
        assert "confusables" in flags_header.split(",")
        body = response.json()
        assert "confusables" in body["flags"]
    finally:
        set_config(initial, replace=True)
