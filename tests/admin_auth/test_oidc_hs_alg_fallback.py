import time
from typing import Any, Dict

import jwt

from app.security import oidc as OIDC


def _make_hs_token(secret: str, claims: Dict[str, Any], alg: str = "HS256") -> str:
    return jwt.encode(claims, secret, algorithm=alg)


def test_verify_id_token_hs256_fallback(monkeypatch):
    monkeypatch.setenv("OIDC_CLIENT_ID", "client-123")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "supersecret")
    monkeypatch.setenv("OIDC_ISSUER", "https://issuer.example.com")

    monkeypatch.setattr(OIDC.config, "OIDC_CLIENT_ID", "client-123", raising=False)
    monkeypatch.setattr(OIDC.config, "OIDC_CLIENT_SECRET", "supersecret", raising=False)
    monkeypatch.setattr(OIDC.config, "OIDC_ISSUER", "https://issuer.example.com", raising=False)

    now = int(time.time())
    claims = {
        "iss": "https://issuer.example.com",
        "aud": "client-123",
        "iat": now - 10,
        "exp": now + 300,
        "email": "user@example.com",
        "name": "User Example",
    }
    token = _make_hs_token("supersecret", claims, "HS256")

    jwks = {"keys": []}

    decoded = OIDC.verify_id_token(token, jwks, now=now)
    assert decoded["email"] == "user@example.com"
    assert decoded["iss"] == "https://issuer.example.com"
    assert decoded["aud"] == "client-123"
