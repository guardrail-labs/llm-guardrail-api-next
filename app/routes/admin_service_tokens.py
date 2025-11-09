from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body, Depends

from app import config
from app.observability import admin_audit as AA
from app.security import service_tokens as ST
from app.security.rbac import require_admin

router = APIRouter(prefix="/admin/api/tokens", tags=["admin-tokens"])


@router.get("")
def list_tokens(_: Dict[str, Any] = Depends(require_admin)) -> Dict[str, Any]:
    client = ST._redis()
    use_redis = config.SERVICE_TOKEN_USE_REDIS and client is not None
    if use_redis and client is not None:
        try:
            revoked = list(client.smembers(f"{config.SERVICE_TOKEN_REDIS_PREFIX}:revoked"))
        except Exception:
            revoked = ST.list_revoked()
            use_redis = False
    else:
        revoked = ST.list_revoked()
    return {
        "revoked_jtis": revoked,
        "stateless": True,
        "revocation_backend": "redis" if use_redis else "memory",
    }


@router.post("/mint")
def mint_token(
    payload: Dict[str, Any] = Body(...),
    user: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    role = str(payload.get("role", "viewer"))
    tenants = payload.get("tenants", "*")
    bots = payload.get("bots", "*")
    ttl_hours = payload.get("ttl_hours")
    out = ST.mint(role=role, tenants=tenants, bots=bots, ttl_hours=ttl_hours)
    AA.record(
        action="token_mint",
        actor_email=(user or {}).get("email"),
        actor_role=(user or {}).get("role"),
        outcome="ok",
        meta={"role": role, "tenants": tenants, "bots": bots, "exp": out["exp"]},
    )
    return {
        "token": out["token"],
        "jti": out["jti"],
        "exp": out["exp"],
        "role": role,
        "tenants": tenants,
        "bots": bots,
    }


@router.post("/revoke")
def revoke_token(
    payload: Dict[str, Any] = Body(...),
    user: Dict[str, Any] = Depends(require_admin),
) -> Dict[str, Any]:
    jti = str(payload.get("jti", ""))
    ST.revoke(jti)
    AA.record(
        action="token_revoke",
        actor_email=(user or {}).get("email"),
        actor_role=(user or {}).get("role"),
        outcome="ok",
        meta={"jti": jti},
    )
    return {"revoked": jti}
