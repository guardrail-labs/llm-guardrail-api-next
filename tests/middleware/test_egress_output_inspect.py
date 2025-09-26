from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, JSONResponse
from starlette.testclient import TestClient

from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware


def make_app():
    app = FastAPI()

    @app.get("/plain")
    async def plain():
        return PlainTextResponse("safe text")

    @app.get("/emoji")
    async def emoji():
        # "secret" encoded as TAGs + CANCEL TAG (E007F)
        tag = "".join(chr(0xE0000 + ord(c)) for c in "secret") + chr(0xE007F)
        return PlainTextResponse(tag)

    @app.get("/html")
    async def html():
        return PlainTextResponse("<p>hi</p>")

    @app.get("/json")
    async def json_out():
        return JSONResponse({"msg": "ok\u200b"})  # zero-width space

    app.add_middleware(EgressOutputInspectMiddleware)
    return app


def test_plain_has_no_flags():
    client = TestClient(make_app())
    r = client.get("/plain")
    assert r.status_code == 200
    assert "X-Guardrail-Egress-Flags" not in r.headers


def test_emoji_sets_flag():
    client = TestClient(make_app())
    r = client.get("/emoji")
    assert r.status_code == 200
    flags = r.headers.get("X-Guardrail-Egress-Flags", "")
    assert "emoji" in flags


def test_html_sets_flag():
    client = TestClient(make_app())
    r = client.get("/html")
    assert r.status_code == 200
    flags = r.headers.get("X-Guardrail-Egress-Flags", "")
    assert "markup" in flags


def test_zero_width_sets_flag():
    client = TestClient(make_app())
    r = client.get("/json")
    assert r.status_code == 200
    flags = r.headers.get("X-Guardrail-Egress-Flags", "")
    assert "zwc" in flags
