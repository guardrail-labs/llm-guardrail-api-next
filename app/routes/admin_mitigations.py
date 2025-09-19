from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from app.security.admin_auth import require_admin
from app.services.mitigation_modes import (
    DEFAULT_MODES,
    delete_modes,
    get_modes,
    set_modes,
)

router = APIRouter(
    prefix="/admin/mitigation_modes",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


def _json_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _normalize_identifier(value: str) -> str:
    return value.strip()


def _validate_tenant_bot(tenant: str, bot: str) -> tuple[str, str] | JSONResponse:
    t = _normalize_identifier(tenant)
    b = _normalize_identifier(bot)
    if not t or not b:
        return _json_error("tenant and bot are required", status_code=400)
    return t, b


def _validate_modes(payload: Dict[str, Any]) -> Dict[str, bool] | JSONResponse:
    if not isinstance(payload, dict):
        return _json_error("modes must be an object", status_code=400)
    cleaned: Dict[str, bool] = {}
    for flag in DEFAULT_MODES:
        value = payload.get(flag, False)
        if value is not False and value is not True:
            return _json_error(f"mode '{flag}' must be a boolean", status_code=400)
        cleaned[flag] = bool(value)
    extra_keys = set(payload.keys()) - set(DEFAULT_MODES.keys())
    if extra_keys:
        return _json_error(
            "unsupported modes: " + ", ".join(sorted(extra_keys)),
            status_code=400,
        )
    return cleaned


@router.get("")
async def read_mitigation_modes(
    tenant: str = Query(default=""), bot: str = Query(default="")
) -> JSONResponse:
    validated = _validate_tenant_bot(tenant, bot)
    if isinstance(validated, JSONResponse):
        return validated
    tenant_id, bot_id = validated
    record = {
        "tenant": tenant_id,
        "bot": bot_id,
        "modes": get_modes(tenant_id, bot_id),
        "version": None,
    }
    return JSONResponse(record)


@router.put("")
async def write_mitigation_modes(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        return _json_error("invalid JSON body", status_code=400)
    if not isinstance(payload, dict):
        return _json_error("invalid JSON body", status_code=400)
    tenant_raw = str(payload.get("tenant") or "")
    bot_raw = str(payload.get("bot") or "")
    validated = _validate_tenant_bot(tenant_raw, bot_raw)
    if isinstance(validated, JSONResponse):
        return validated
    tenant_id, bot_id = validated
    modes_raw = payload.get("modes", {})
    modes = _validate_modes(modes_raw)
    if isinstance(modes, JSONResponse):
        return modes
    saved = set_modes(tenant_id, bot_id, modes)
    record = {
        "tenant": tenant_id,
        "bot": bot_id,
        "modes": saved,
        "version": payload.get("version"),
    }
    return JSONResponse(record)


@router.delete("")
async def remove_mitigation_modes(
    tenant: str = Query(default=""), bot: str = Query(default="")
) -> JSONResponse:
    validated = _validate_tenant_bot(tenant, bot)
    if isinstance(validated, JSONResponse):
        return validated
    tenant_id, bot_id = validated
    delete_modes(tenant_id, bot_id)
    return JSONResponse({"deleted": True})
