from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.ingress_trace_guard import IngressTraceGuardMiddleware


def make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping")
    async def ping():
        return PlainTextResponse("pong")

    app.add_middleware(IngressTraceGuardMiddleware)
    return app


def test_generates_request_id_when_missing():
    client = TestClient(make_app())
    r = client.get("/ping")
    assert r.status_code == 200
    rid = r.headers.get("x-request-id", "")
    assert isinstance(rid, str) and 16 <= len(rid) <= 64


def test_keeps_valid_request_id():
    client = TestClient(make_app())
    r = client.get("/ping", headers={"X-Request-ID": "abcdef0123456789abcdef0123456789"})
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == "abcdef0123456789abcdef0123456789"


def test_replaces_invalid_request_id():
    client = TestClient(make_app())
    r = client.get("/ping", headers={"X-Request-ID": "not valid!!!"})
    assert r.status_code == 200
    rid = r.headers.get("x-request-id", "")
    assert rid != "not valid!!!" and 16 <= len(rid) <= 64


def test_drops_invalid_traceparent():
    client = TestClient(make_app())
    bad = "00-zzzzzz-aaaaaaaaaaaaaaaa-01"
    r = client.get("/ping", headers={"traceparent": bad})
    assert r.status_code == 200
    assert "traceparent" not in {k.lower() for k in r.headers}


def test_propagates_valid_traceparent():
    client = TestClient(make_app())
    good = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    r = client.get("/ping", headers={"traceparent": good})
    assert r.status_code == 200
    assert r.headers.get("traceparent") == good
