from __future__ import annotations

from fastapi import APIRouter
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


def _parse_cookie(header: str) -> dict[str, str | bool]:
    parts = [part.strip() for part in header.split(";") if part.strip()]
    if not parts:
        return {}
    attrs: dict[str, str | bool] = {}
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


def test_secure_cookie_attributes_default():
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
        assert sess_attrs.get("path") == "/admin"
        assert int(sess_attrs.get("max-age", "0")) == 1800

        assert csrf_attrs.get("value")
        assert csrf_attrs.get("secure") is True
        assert csrf_attrs.get("httponly") is not True
        assert csrf_attrs.get("samesite", "").lower() == "strict"
        assert csrf_attrs.get("path") == "/admin"
        assert int(csrf_attrs.get("max-age", "0")) == 1800


def test_ttl_clamped_bounds(monkeypatch):
    monkeypatch.setenv("ADMIN_SESSION_TTL_SECONDS", "120")
    with _make_client() as client:
        resp = client.get("/admin/ping")
        set_cookies = _get_set_cookie_headers(resp)
        sess = next(c for c in set_cookies if c.startswith("admin_sess="))
        csrf = next(c for c in set_cookies if c.startswith("admin_csrf="))
        assert int(_parse_cookie(sess).get("max-age", "0")) == 300
        assert int(_parse_cookie(csrf).get("max-age", "0")) == 300

    monkeypatch.setenv("ADMIN_SESSION_TTL_SECONDS", "999999")
    with _make_client() as client:
        resp = client.get("/admin/ping")
        set_cookies = _get_set_cookie_headers(resp)
        sess = next(c for c in set_cookies if c.startswith("admin_sess="))
        csrf = next(c for c in set_cookies if c.startswith("admin_csrf="))
        assert int(_parse_cookie(sess).get("max-age", "0")) == 86400
        assert int(_parse_cookie(csrf).get("max-age", "0")) == 86400
