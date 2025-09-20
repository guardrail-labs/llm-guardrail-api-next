from __future__ import annotations

from fastapi import APIRouter, Response
from starlette.testclient import TestClient

from app.main import create_app


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


def _make_client() -> TestClient:
    app = create_app()
    router = APIRouter()

    @router.get("/admin/ping")
    def _ping():  # pragma: no cover - simple test hook
        return {"ok": True}

    app.include_router(router)
    return TestClient(app)


def test_middleware_does_not_duplicate_csrf_when_handler_sets_it():
    app = create_app()
    router = APIRouter()

    @router.get("/admin/test-set-csrf")
    def _handler():
        resp = Response("ok")
        resp.set_cookie("admin_csrf", "handler-token", path="/", samesite="strict")
        return resp

    app.include_router(router)

    with TestClient(app) as client:
        resp = client.get("/admin/test-set-csrf")
        assert resp.status_code == 200
        cookies = _get_set_cookie_headers(resp)
        csrf_set = [c for c in cookies if c.startswith("admin_csrf=")]
        assert len(csrf_set) == 1
        assert "admin_csrf=handler-token" in csrf_set[0]


def test_csrf_rotates_only_on_new_session():
    with _make_client() as client:
        resp1 = client.get("/admin/ping")
        assert resp1.status_code in {200, 302, 401}
        c1 = resp1.cookies.get("admin_csrf")
        s1 = resp1.cookies.get("admin_sess")
        assert c1 and s1

        client.cookies.set("admin_sess", s1, path="/admin")
        client.cookies.set("admin_csrf", c1, path="/admin")

        resp2 = client.get("/admin/ping")
        assert resp2.status_code in {200, 302, 401}
        c2 = resp2.cookies.get("admin_csrf") or c1
        assert c2 == c1


def test_no_secure_when_dev_toggle_off(monkeypatch):
    monkeypatch.setenv("ADMIN_COOKIE_SECURE", "0")
    app = create_app()
    router = APIRouter()

    @router.get("/admin/no-secure")
    def _handler_no_secure():  # pragma: no cover - simple test hook
        return {"ok": True}

    app.include_router(router)

    with TestClient(app) as client:
        resp = client.get("/admin/no-secure")
        assert resp.status_code in {200, 302, 401}
        set_cookies = _get_set_cookie_headers(resp)
        blob = " ".join(set_cookies)
        assert "admin_sess=" in blob and "Secure" not in blob
        assert "admin_csrf=" in blob and "Secure" not in blob
