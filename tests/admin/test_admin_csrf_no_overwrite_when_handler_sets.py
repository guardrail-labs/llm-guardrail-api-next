from __future__ import annotations

from fastapi import APIRouter, Response
from starlette.testclient import TestClient

from app.main import create_app

from .test_admin_session_hardening import _get_set_cookie_headers, _parse_cookie


def _make_custom_client() -> TestClient:
    app = create_app()
    router = APIRouter()

    @router.get("/admin/custom")
    def _custom():  # pragma: no cover - test helper
        resp = Response(content="ok")
        resp.set_cookie("admin_csrf", "HANDLER_VALUE")
        return resp

    app.include_router(router)
    return TestClient(app, base_url="https://testserver")


def test_does_not_overwrite_handler_set_cookie():
    with _make_custom_client() as client:
        resp = client.get("/admin/custom")
        assert resp.status_code in {200, 302, 401}

        set_cookies = _get_set_cookie_headers(resp)
        csrf_headers = [blob for blob in set_cookies if blob.startswith("admin_csrf=")]
        assert len(csrf_headers) == 1

        parsed = _parse_cookie(csrf_headers[0])
        assert parsed.get("value") == "HANDLER_VALUE"
