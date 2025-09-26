import asyncio
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.datastructures import State
from starlette.testclient import TestClient
from starlette.types import Message

from app.middleware.ingress_path_guard import IngressPathGuardMiddleware


def make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ok/hello")
    async def ok():
        return PlainTextResponse("ok")

    app.add_middleware(IngressPathGuardMiddleware)
    return app


def test_normal_path_allowed():
    client = TestClient(make_app())
    r = client.get("/ok/hello")
    assert r.status_code == 200
    assert r.text == "ok"


def _run_path(path: str) -> tuple[int, bytes]:
    app = make_app()

    async def _call() -> tuple[int, bytes]:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "headers": [(b"host", b"testserver")],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "extensions": {"http.response.debug": {}},
            "state": State(),
            "app": app,
        }

        status = {"code": 0}
        body: list[bytes] = []

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            elif message["type"] == "http.response.body":
                body.append(message.get("body", b""))

        await app(scope, receive, send)
        return status["code"], b"".join(body)

    return asyncio.run(_call())


def test_simple_traversal_blocked():
    status, _ = _run_path("/ok/../secret")
    assert status == 400


def test_double_encoded_traversal_blocked():
    # %252e%252e => %2e%2e => ".."
    status, _ = _run_path("/ok/%252e%252e/secret")
    assert status == 400


def test_homoglyph_slash_blocked():
    # U+2215 DIVISION SLASH instead of "/"
    homog = "\u2215"
    status, _ = _run_path(f"/ok{homog}..{homog}secret")
    assert status == 400
