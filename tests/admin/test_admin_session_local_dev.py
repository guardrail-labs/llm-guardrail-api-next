from __future__ import annotations

from fastapi import APIRouter, Response
from starlette.testclient import TestClient

from app.main import create_app


def _make_client() -> TestClient:
    app = create_app()
    router = APIRouter()

    @router.get("/admin/ping")
    def _ping():  # pragma: no cover - simple test hook
        return {"ok": True}

    app.include_router(router)
    return TestClient(app, base_url="https://testserver")


def _get_set_cookie_headers(resp) -> list[str]:
    vals: list[str] = []
    raw = getattr(resp.headers, "raw", None)
    if raw:
        for k, v in raw:
            try:
                key = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
                if key.lower() != "set-cookie":
                    continue
                if isinstance(v, (bytes, bytearray)):
                    vals.append(v.decode("latin-1"))
                else:
                    vals.append(str(v))
            except Exception:
                continue
    if not vals:
        raw_headers = getattr(resp, "raw_headers", None) or []
        for k, v in raw_headers:
            try:
                key = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
                if key.lower() != "set-cookie":
                    continue
                if isinstance(v, (bytes, bytearray)):
                    vals.append(v.decode("latin-1"))
                else:
                    vals.append(str(v))
            except Exception:
                continue
    if not vals:
        header_val = resp.headers.get("set-cookie")
        if header_val:
            if isinstance(header_val, (list, tuple)):
                vals = [str(v) for v in header_val]
            else:
                vals = [str(header_val)]
    return vals


def test_secure_flag_disabled_for_local_dev(monkeypatch):
    monkeypatch.setenv("ADMIN_COOKIE_SECURE", "0")
    with _make_client() as client:
        resp = client.get("/admin/ping")
        assert resp.status_code in {200, 302, 401}
        set_cookies = _get_set_cookie_headers(resp)
        assert all("Secure" not in cookie for cookie in set_cookies)
        assert all("samesite=strict" in cookie.lower() for cookie in set_cookies)
        assert all("Path=/admin" in cookie for cookie in set_cookies)


def test_does_not_overwrite_handler_cookie(monkeypatch):
    monkeypatch.setenv("ADMIN_COOKIE_SECURE", "0")
    app = create_app()
    router = APIRouter()

    @router.get("/admin/custom-csrf")
    def _handler():
        resp = Response("ok")
        resp.set_cookie("admin_csrf", "handler-token", path="/admin", samesite="strict")
        return resp

    app.include_router(router)

    with TestClient(app) as client:
        resp = client.get("/admin/custom-csrf")
        assert resp.status_code in {200, 302, 401}
        assert resp.cookies.get("admin_csrf") == "handler-token"
        set_cookies = _get_set_cookie_headers(resp)
        csrf_headers = [cookie for cookie in set_cookies if cookie.startswith("admin_csrf=")]
        assert len(csrf_headers) == 1
        assert "handler-token" in csrf_headers[0]
