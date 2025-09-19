from __future__ import annotations

from typing import Dict

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


def _parse_cookie(header: str) -> Dict[str, str | bool]:
    parts = [part.strip() for part in header.split(";") if part.strip()]
    if not parts:
        return {}
    attrs: Dict[str, str | bool] = {}
    name, _, value = parts[0].partition("=")
    attrs["name"] = name
    attrs["value"] = value
    for segment in parts[1:]:
        if "=" in segment:
            k, v = segment.split("=", 1)
            attrs[k.lower()] = v
        else:
            attrs[segment.lower()] = True
    return attrs


def _make_client() -> TestClient:
    app = create_app()
    router = APIRouter()

    @router.get("/admin/ping")
    def _ping():  # pragma: no cover - simple test hook
        return {"ok": True}

    app.include_router(router)
    return TestClient(app)


def test_cookie_attributes_present():
    with _make_client() as client:
        resp = client.get("/admin/ping")
        assert resp.status_code in {200, 302, 401}
        set_cookies = _get_set_cookie_headers(resp)
        sess = next(c for c in set_cookies if c.startswith("admin_sess="))
        csrf = next(c for c in set_cookies if c.startswith("admin_csrf="))

        sess_attrs = _parse_cookie(sess)
        csrf_attrs = _parse_cookie(csrf)

        assert sess_attrs.get("value")
        assert sess_attrs.get("secure") is True
        assert sess_attrs.get("httponly") is True
        assert sess_attrs.get("samesite", "").lower() == "strict"
        assert int(sess_attrs.get("max-age", "0")) == 1200

        assert csrf_attrs.get("value")
        assert csrf_attrs.get("secure") is True
        assert csrf_attrs.get("httponly") is not True
        assert csrf_attrs.get("samesite", "").lower() == "strict"
        assert int(csrf_attrs.get("max-age", "0")) == 1200


def test_ttl_honored(monkeypatch):
    monkeypatch.setenv("ADMIN_SESSION_TTL_SECONDS", "60")
    with _make_client() as client:
        resp = client.get("/admin/ping")
        set_cookies = _get_set_cookie_headers(resp)
        sess = next(c for c in set_cookies if c.startswith("admin_sess="))
        csrf = next(c for c in set_cookies if c.startswith("admin_csrf="))

        assert int(_parse_cookie(sess).get("max-age", "0")) == 60
        assert int(_parse_cookie(csrf).get("max-age", "0")) == 60


def test_csrf_rotates_on_new_session():
    with _make_client() as client:
        resp1 = client.get("/admin/ping")
        assert resp1.status_code in {200, 302, 401}
        sess1 = resp1.cookies.get("admin_sess")
        csrf1 = resp1.cookies.get("admin_csrf")
        assert sess1 and csrf1

        client.cookies.clear()

        resp2 = client.get("/admin/ping")
        assert resp2.status_code in {200, 302, 401}
        sess2 = resp2.cookies.get("admin_sess")
        csrf2 = resp2.cookies.get("admin_csrf")

        assert sess2 and csrf2
        assert sess1 != sess2
        assert csrf1 != csrf2


def test_does_not_clobber_handler_set_csrf():
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
        csrf_header = next(c for c in set_cookies if c.startswith("admin_csrf="))
        assert "handler-token" in csrf_header


def test_local_dev_override(monkeypatch):
    monkeypatch.setenv("ADMIN_COOKIE_INSECURE", "1")
    with _make_client() as client:
        resp = client.get("/admin/ping")
        set_cookies = _get_set_cookie_headers(resp)
        sess_attrs = _parse_cookie(next(c for c in set_cookies if c.startswith("admin_sess=")))
        csrf_attrs = _parse_cookie(next(c for c in set_cookies if c.startswith("admin_csrf=")))

        assert "secure" not in sess_attrs
        assert "secure" not in csrf_attrs
