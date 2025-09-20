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


def test_new_session_rotates_once():
    with _make_client() as client:
        resp1 = client.get("/admin/ping")
        assert resp1.status_code in {200, 302, 401}
        sess1 = resp1.cookies.get("admin_sess")
        csrf1 = resp1.cookies.get("admin_csrf")
        assert sess1 and csrf1

        resp2 = client.get("/admin/ping")
        assert resp2.status_code in {200, 302, 401}
        sess2 = resp2.cookies.get("admin_sess")
        csrf2 = resp2.cookies.get("admin_csrf") or csrf1

        assert sess2 == sess1
        assert csrf2 == csrf1

        set_cookies = _get_set_cookie_headers(resp2)
        csrf_headers = [blob for blob in set_cookies if blob.startswith("admin_csrf=")]
        assert len(csrf_headers) == 1
        parsed = _parse_cookie(csrf_headers[0])
        assert parsed.get("value") == csrf1


def test_recovers_missing_csrf():
    with _make_client() as client:
        resp1 = client.get("/admin/ping")
        assert resp1.status_code in {200, 302, 401}
        sess1 = resp1.cookies.get("admin_sess")
        csrf1 = resp1.cookies.get("admin_csrf")
        assert sess1 and csrf1

        del client.cookies["admin_csrf"]

        resp2 = client.get("/admin/ping")
        assert resp2.status_code in {200, 302, 401}
        sess2 = resp2.cookies.get("admin_sess")
        csrf2 = resp2.cookies.get("admin_csrf")

        assert sess2 == sess1
        assert csrf2 and csrf2 != csrf1

        set_cookies = _get_set_cookie_headers(resp2)
        csrf_headers = [blob for blob in set_cookies if blob.startswith("admin_csrf=")]
        assert len(csrf_headers) == 1
        assert csrf2 in csrf_headers[0]
