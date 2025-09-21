import base64
import itertools
import time
import urllib.parse

import httpx
import jwt
import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app import config
from app.main import create_app
from app.security import oidc as oidc_helpers, rbac


def test_map_role_supports_nested_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "OIDC_ROLE_CLAIM", "realm_access.roles", raising=False)
    monkeypatch.setattr(
        config,
        "OIDC_ROLE_MAP",
        {"admin": ["realm-admin"], "viewer": ["viewer"]},
        raising=False,
    )
    monkeypatch.setattr(config, "OIDC_DEFAULT_ROLE", "viewer", raising=False)

    claims = {"realm_access": {"roles": ["realm-admin", "other"]}}
    assert oidc_helpers.map_role(claims) == "admin"

    fallback_claims = {"realm_access": {"roles": ["other"]}}
    assert oidc_helpers.map_role(fallback_claims) == "viewer"


def test_verify_id_token_with_local_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = b"super-secret"
    key_b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("utf-8")
    jwks = {
        "keys": [
            {
                "kty": "oct",
                "kid": "test",
                "alg": "HS256",
                "k": key_b64,
            }
        ]
    }
    now = int(time.time())
    payload = {
        "sub": "user",
        "aud": "client-id",
        "iss": "https://issuer.example",
        "exp": now + 60,
        "iat": now,
        "nonce": "abc123",
    }
    headers = {"kid": "test", "alg": "HS256"}
    token = jwt.encode(payload, secret, algorithm="HS256", headers=headers)

    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "client-id", raising=False)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.example", raising=False)

    claims = oidc_helpers.verify_id_token(token, jwks, now=now)
    assert claims["sub"] == "user"
    assert claims["nonce"] == "abc123"


def test_oidc_login_callback_sets_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "OIDC_ENABLED", True, raising=False)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://example.com/oidc", raising=False)
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "cid", raising=False)
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "secret", raising=False)
    monkeypatch.setattr(config, "OIDC_SCOPES", "openid email profile", raising=False)
    monkeypatch.setattr(config, "OIDC_REDIRECT_PATH", "/admin/auth/callback", raising=False)
    monkeypatch.setattr(config, "OIDC_ROLE_CLAIM", "roles", raising=False)
    monkeypatch.setattr(config, "OIDC_ROLE_MAP", {"admin": ["admin"]}, raising=False)
    monkeypatch.setattr(config, "OIDC_DEFAULT_ROLE", "viewer", raising=False)
    monkeypatch.setattr(config, "OIDC_EMAIL_CLAIM", "email", raising=False)
    monkeypatch.setattr(config, "OIDC_NAME_CLAIM", "name", raising=False)
    monkeypatch.setattr(config, "OIDC_LOGOUT_URL", "", raising=False)
    monkeypatch.setenv("ADMIN_SESSION_SECRET", "session-secret")
    monkeypatch.setenv("ADMIN_COOKIE_SECURE", "0")

    async def fake_openid_config() -> dict[str, str]:
        return {
            "jwks_uri": "https://example.com/jwks",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
        }

    async def fake_jwks(_url: str) -> dict[str, object]:
        return {"keys": []}

    def fake_verify(
        id_token: str,
        jwks: dict[str, object],
        now: int | None = None,
    ) -> dict[str, object]:
        return {
            "email": "alice@example.com",
            "name": "Alice",
            "roles": ["admin"],
            "nonce": "nonce-token",
        }

    monkeypatch.setattr(oidc_helpers, "fetch_openid_config", fake_openid_config, raising=False)
    monkeypatch.setattr(oidc_helpers, "fetch_jwks", fake_jwks, raising=False)
    monkeypatch.setattr(oidc_helpers, "verify_id_token", fake_verify, raising=False)

    from app.routes import admin_auth_oidc

    tokens = itertools.cycle(["session-cookie", "state-token", "nonce-token"])
    monkeypatch.setattr(
        admin_auth_oidc.secrets,
        "token_urlsafe",
        lambda _: next(tokens),
        raising=False,
    )

    class _FakeResponse:
        def __init__(self, data: dict[str, object]):
            self._data = data
            self.status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._data

    async def fake_post(self, url: str, data: dict[str, object] | None = None):
        return _FakeResponse({"id_token": "token"})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post, raising=False)

    app = create_app()
    router = APIRouter()

    @router.get("/admin/test-whoami")
    def whoami_route(_: dict[str, object] = Depends(rbac.require_viewer)) -> dict[str, object]:
        user = _ or {}
        return {"email": user.get("email"), "role": user.get("role")}

    app.include_router(router)

    with TestClient(app) as client:
        login = client.get("/admin/auth/login", follow_redirects=False)
        assert login.status_code in {302, 307}
        params = urllib.parse.parse_qs(urllib.parse.urlparse(login.headers["location"]).query)
        state = params.get("state", [None])[0]
        assert state == "state-token"

        callback = client.get(
            "/admin/auth/callback",
            params={"code": "code", "state": state},
            follow_redirects=False,
        )
        assert callback.status_code in {302, 303, 307}

        whoami_resp = client.get("/admin/test-whoami")
        assert whoami_resp.status_code == 200
        payload = whoami_resp.json()
        assert payload["role"] == "admin"
        assert payload.get("email")

        csrf_token = client.cookies.get("ui_csrf") or ""
        logout = client.post("/admin/auth/logout", data={"csrf_token": csrf_token})
        assert logout.status_code in {200, 204, 302}

        after = client.get("/admin/test-whoami")
        assert after.status_code == 401
