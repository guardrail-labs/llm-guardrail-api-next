from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional, cast

import httpx
import jwt
from jwt import PyJWTError, algorithms as jwt_algorithms

from app import config


class OIDCError(Exception):
    """Raised when OIDC configuration or verification fails."""


def _openid_config_url(issuer: str) -> str:
    base = issuer.rstrip("/")
    return f"{base}/.well-known/openid-configuration"


async def fetch_openid_config() -> Dict[str, Any]:
    """Fetch the OpenID configuration for the configured issuer."""

    if not config.OIDC_ISSUER:
        raise OIDCError("OIDC issuer not configured")

    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(_openid_config_url(config.OIDC_ISSUER))
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise OIDCError("Invalid OpenID configuration payload")

    try:
        jwks_uri = data["jwks_uri"]
        auth_endpoint = data["authorization_endpoint"]
    except KeyError as exc:  # pragma: no cover - defensive guard
        raise OIDCError(f"OpenID configuration missing field: {exc}") from exc

    result: Dict[str, Any] = {
        "jwks_uri": jwks_uri,
        "authorization_endpoint": auth_endpoint,
    }
    token_endpoint = data.get("token_endpoint")
    if token_endpoint:
        result["token_endpoint"] = token_endpoint
    userinfo_endpoint = data.get("userinfo_endpoint")
    if userinfo_endpoint:
        result["userinfo_endpoint"] = userinfo_endpoint
    return result


async def fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    """Retrieve the JWKS document referenced by the issuer."""

    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        raise OIDCError("Invalid JWKS payload")
    return cast(Dict[str, Any], payload)


def _candidate_keys(jwks: Dict[str, Any], kid: Optional[str]) -> Iterable[Dict[str, Any]]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, Iterable):
        return []
    if kid:
        matched = [entry for entry in keys if isinstance(entry, dict) and entry.get("kid") == kid]
        if matched:
            return matched
    return [entry for entry in keys if isinstance(entry, dict)]


def _load_key(entry: Dict[str, Any], alg: str):
    try:
        algorithm_cls = jwt_algorithms.get_default_algorithms()[alg]
    except KeyError as exc:
        raise OIDCError(f"Unsupported signing algorithm: {alg}") from exc
    try:
        return algorithm_cls.from_jwk(json.dumps(entry))
    except Exception as exc:  # pragma: no cover - algorithm specific errors
        raise OIDCError("Unable to parse signing key from JWKS") from exc


def verify_id_token(
    id_token: str,
    jwks: Dict[str, Any],
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify an ID token using the provided JWKS document."""

    try:
        header = jwt.get_unverified_header(id_token)
    except PyJWTError as exc:
        raise OIDCError("Malformed ID token header") from exc

    alg = header.get("alg")
    if not isinstance(alg, str):
        raise OIDCError("ID token missing signing algorithm")

    kid = header.get("kid") if isinstance(header, dict) else None
    candidates = list(_candidate_keys(jwks, kid))
    if not candidates:
        if alg.upper().startswith("HS"):
            secret = config.OIDC_CLIENT_SECRET
            if not secret:
                raise OIDCError("HMAC-signed ID token but OIDC_CLIENT_SECRET is not set")

            audience = config.OIDC_CLIENT_ID or None
            issuer = config.OIDC_ISSUER or None
            hmac_decode_kwargs: Dict[str, Any] = {
                "algorithms": [alg],
                "audience": ([audience] if audience else None),
                "issuer": issuer,
                "options": {
                    "verify_aud": bool(audience),
                    "verify_iss": bool(issuer),
                },
                "leeway": 30,
            }
            if now is not None:
                hmac_decode_kwargs["current_time"] = now
            try:
                decoded = jwt.decode(id_token, key=secret, **hmac_decode_kwargs)
            except PyJWTError as exc:
                raise OIDCError("Unable to verify HMAC-signed ID token") from exc
            if not isinstance(decoded, dict):
                raise OIDCError("Invalid ID token claims")
            return cast(Dict[str, Any], decoded)

        raise OIDCError("No signing keys available for ID token")

    audience = config.OIDC_CLIENT_ID or None
    issuer = config.OIDC_ISSUER or None
    last_error: Exception | None = None
    for entry in candidates:
        try:
            key = _load_key(entry, alg)
        except OIDCError as exc:
            last_error = exc
            continue

        decode_kwargs: Dict[str, Any] = {
            "algorithms": [alg],
            "audience": audience,
            "issuer": issuer,
            "options": {"verify_aud": bool(audience)},
            "leeway": 30,
        }
        if now is not None:
            decode_kwargs["current_time"] = now
        try:
            decoded = jwt.decode(id_token, key=key, **decode_kwargs)
            if not isinstance(decoded, dict):
                raise OIDCError("Invalid ID token claims")
            return cast(Dict[str, Any], decoded)
        except PyJWTError as exc:
            last_error = exc
            continue

    raise OIDCError(f"Unable to verify id_token: {last_error}")


def _get_claim(claims: Dict[str, Any], path: str) -> Any:
    current: Any = claims
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def map_role(claims: Dict[str, Any]) -> str:
    """Map token claims to an application role using configured aliases."""

    raw_roles = _get_claim(claims, config.OIDC_ROLE_CLAIM)
    roles: list[str] = []
    if isinstance(raw_roles, list):
        roles = [str(item) for item in raw_roles if item is not None]
    elif isinstance(raw_roles, str):
        roles = [raw_roles]

    role_map = config.OIDC_ROLE_MAP if isinstance(config.OIDC_ROLE_MAP, dict) else {}
    for target_role, aliases in role_map.items():
        if isinstance(aliases, (list, tuple, set)):
            candidates = [str(alias) for alias in aliases]
        elif aliases is None:
            candidates = []
        else:
            candidates = [str(aliases)]
        for alias in candidates:
            if alias in roles:
                return str(target_role)
    return config.OIDC_DEFAULT_ROLE


__all__ = [
    "OIDCError",
    "fetch_openid_config",
    "fetch_jwks",
    "map_role",
    "verify_id_token",
]
