"""Service account token helpers."""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional, cast

import jwt

from app import config


class TokenError(Exception):
    """Raised when minting or verifying a service token fails."""


def _now() -> int:
    return int(time.time())


def mint(
    *,
    role: str,
    tenants: List[str] | str = "*",
    bots: List[str] | str = "*",
    ttl_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """Mint a new service token for the provided role and scope."""

    if not config.SERVICE_TOKEN_SECRET:
        raise TokenError("SERVICE_TOKEN_SECRET not configured")
    jti = str(uuid.uuid4())
    ttl = int(ttl_hours or config.SERVICE_TOKEN_TTL_HOURS)
    exp = _now() + int(3600 * ttl)
    claims: Dict[str, Any] = {
        "iss": config.SERVICE_TOKEN_ISSUER,
        "aud": config.SERVICE_TOKEN_AUDIENCE,
        "sub": f"svc:{jti}",
        "jti": jti,
        "role": role,
        "tenants": tenants,
        "bots": bots,
        "iat": _now(),
        "exp": exp,
        "typ": "guardrail/sa",
    }
    token = jwt.encode(claims, config.SERVICE_TOKEN_SECRET, algorithm="HS256")
    return {"token": token, "jti": jti, "exp": exp, "claims": claims}


def verify(token: str) -> Dict[str, Any]:
    """Verify a token and return its claims."""

    try:
        claims = cast(
            Dict[str, Any],
            jwt.decode(
                token,
                config.SERVICE_TOKEN_SECRET,
                algorithms=["HS256"],
                audience=config.SERVICE_TOKEN_AUDIENCE,
                issuer=config.SERVICE_TOKEN_ISSUER,
                leeway=30,
            ),
        )
    except Exception as exc:  # pragma: no cover - delegated to jwt
        raise TokenError(f"invalid token: {exc}") from exc
    if is_revoked(str(claims.get("jti", ""))):
        raise TokenError("token revoked")
    return claims


_REV_MEM: set[str] = set()


def _redis():
    try:
        import redis

        return redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
        )
    except Exception:  # pragma: no cover - optional dependency
        return None


def revoke(jti: str) -> None:
    """Mark a token identifier as revoked."""

    if not jti:
        return
    if config.SERVICE_TOKEN_USE_REDIS:
        client = _redis()
        if client:
            client.sadd(f"{config.SERVICE_TOKEN_REDIS_PREFIX}:revoked", jti)
            return
    _REV_MEM.add(jti)


def is_revoked(jti: str) -> bool:
    if not jti:
        return True
    if config.SERVICE_TOKEN_USE_REDIS:
        client = _redis()
        if client:
            return bool(client.sismember(f"{config.SERVICE_TOKEN_REDIS_PREFIX}:revoked", jti))
    return jti in _REV_MEM


def list_revoked() -> List[str]:
    """Return the revoked token identifiers for diagnostics."""

    if config.SERVICE_TOKEN_USE_REDIS:
        client = _redis()
        if client:
            members = client.smembers(f"{config.SERVICE_TOKEN_REDIS_PREFIX}:revoked")
            if isinstance(members, list):
                return members
            if isinstance(members, set):
                return list(members)
            return list(members or [])
    return list(_REV_MEM)


def reset_memory_store() -> None:
    """Clear the in-memory revocation cache (useful for tests)."""

    _REV_MEM.clear()
