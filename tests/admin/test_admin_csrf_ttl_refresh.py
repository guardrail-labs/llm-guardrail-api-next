from __future__ import annotations

from .test_admin_csrf_rotation import _make_client
from .test_admin_session_hardening import _get_set_cookie_headers, _parse_cookie


def test_csrf_cookie_ttl_refreshes_each_request():
    with _make_client() as client:
        resp1 = client.get("/admin/ping")
        assert resp1.status_code in {200, 302, 401}
        sess1 = resp1.cookies.get("admin_sess")
        csrf1 = resp1.cookies.get("admin_csrf")
        assert sess1 and csrf1

        resp2 = client.get("/admin/ping")
        assert resp2.status_code in {200, 302, 401}

        set_cookies = _get_set_cookie_headers(resp2)
        sess_cookie = next(c for c in set_cookies if c.startswith("admin_sess="))
        csrf_cookie = next(c for c in set_cookies if c.startswith("admin_csrf="))

        sess_attrs = _parse_cookie(sess_cookie)
        csrf_attrs = _parse_cookie(csrf_cookie)

        assert sess_attrs.get("value") == sess1
        assert csrf_attrs.get("value") == csrf1

        assert int(sess_attrs.get("max-age", "0")) == 1800
        assert int(csrf_attrs.get("max-age", "0")) == 1800

        assert sess_attrs.get("path") == "/admin"
        assert csrf_attrs.get("path") == "/admin"

        assert sess_attrs.get("samesite", "").lower() == "strict"
        assert csrf_attrs.get("samesite", "").lower() == "strict"

        assert sess_attrs.get("secure") is True
        assert csrf_attrs.get("secure") is True

        assert sess_attrs.get("httponly") is True
        assert csrf_attrs.get("httponly") is not True
