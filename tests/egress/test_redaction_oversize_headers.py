from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import Response
from fastapi.testclient import TestClient


def _mk_app() -> FastAPI:
    app = FastAPI()

    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    @app.get("/big-cookies")
    def big_cookies() -> Response:
        body = b"A" * (2 * 1024 * 1024)
        resp = Response(content=body, media_type="text/plain; charset=utf-8")
        resp.headers.append("Set-Cookie", "a=1; Path=/; HttpOnly")
        resp.headers.append("Set-Cookie", "b=2; Path=/; Secure")
        return resp

    return app

def _get_all_header_values(response: Any, name: str) -> list[str]:
    def _values_from(source: Any, attr: str) -> list[str]:
        getter = getattr(source, attr, None)
        if getter is None:
            return []
        for header_name in (name, name.lower(), name.title()):
            values = getter(header_name)
            if values:
                if isinstance(values, (list, tuple)):
                    return [str(v) for v in values]
                return [str(values)]
        return []

    values = _values_from(response.headers, "getlist")
    if values:
        return values
    values = _values_from(response.headers, "get_all")
    if values:
        return values

    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None:
        values = _values_from(raw_headers, "getlist")
        if values:
            return values
        values = _values_from(raw_headers, "get_all")
        if values:
            return values

    return [
        str(value)
        for key, value in response.headers.items()
        if key.lower() == name.lower()
    ]


def test_oversize_keeps_duplicate_headers(monkeypatch) -> None:
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    monkeypatch.setenv("EGRESS_REDACT_MAX_BYTES", "1048576")
    client = TestClient(_mk_app())
    response = client.get("/big-cookies")

    assert response.status_code == 200
    assert response.headers.get("X-Redaction-Skipped") == "oversize"

    cookies = _get_all_header_values(response, "set-cookie")
    assert any("a=1" in cookie for cookie in cookies)
    assert any("b=2" in cookie for cookie in cookies)

    content_type = response.headers.get("content-type", "")
    assert content_type.lower().startswith("text/plain;")
    assert "charset=" in content_type.lower()

