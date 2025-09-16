from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import require_auth
from app.services.config_store import get_config, set_config

router = APIRouter(prefix="/admin", tags=["admin-config"])


def _parse_bool(raw: Any) -> Tuple[Optional[bool], Optional[str]]:
    if isinstance(raw, bool):
        return raw, None
    if isinstance(raw, (int, float)):
        return bool(raw), None
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True, None
        if s in {"0", "false", "no", "n", "off"}:
            return False, None
    return None, "must be a boolean"


def _parse_int(raw: Any) -> Tuple[Optional[int], Optional[str]]:
    if raw is None or raw == "":
        return None, "required"
    try:
        val = int(float(str(raw).strip()))
    except Exception:
        return None, "must be an integer"
    return val, None


def _parse_float(raw: Any) -> Tuple[Optional[float], Optional[str]]:
    if raw is None or raw == "":
        return None, "required"
    try:
        val = float(str(raw).strip())
    except Exception:
        return None, "must be a float"
    return val, None


def _normalize_payload(data: Mapping[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    patch: Dict[str, Any] = {}
    errors: Dict[str, str] = {}

    if "shadow_enable" in data:
        bool_val, bool_err = _parse_bool(data.get("shadow_enable"))
        if bool_err:
            errors["shadow_enable"] = bool_err
        elif bool_val is not None:
            patch["shadow_enable"] = bool_val

    if "shadow_policy_path" in data:
        path_raw = data.get("shadow_policy_path")
        if path_raw is None:
            patch["shadow_policy_path"] = ""
        else:
            patch["shadow_policy_path"] = str(path_raw).strip()

    if "shadow_timeout_ms" in data:
        int_val, int_err = _parse_int(data.get("shadow_timeout_ms"))
        if int_err:
            errors["shadow_timeout_ms"] = int_err
        elif int_val is not None and int_val >= 0:
            patch["shadow_timeout_ms"] = int_val
        else:
            errors["shadow_timeout_ms"] = "must be non-negative"

    if "shadow_sample_rate" in data:
        float_val, float_err = _parse_float(data.get("shadow_sample_rate"))
        if float_err:
            errors["shadow_sample_rate"] = float_err
        elif float_val is not None:
            if float_val < 0.0 or float_val > 1.0:
                errors["shadow_sample_rate"] = "must be between 0 and 1"
            else:
                patch["shadow_sample_rate"] = float_val

    return patch, errors


@router.get("/config")
def get_runtime_config(_: None = Depends(require_auth)) -> JSONResponse:
    return JSONResponse(get_config())


@router.post("/config")
async def update_runtime_config(
    request: Request, _: None = Depends(require_auth)
) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid json")

    if not isinstance(payload, Mapping):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload")

    patch, errors = _normalize_payload(payload)
    if patch:
        set_config(patch)
    cfg = get_config()
    return JSONResponse({"ok": not errors, "errors": errors, "config": cfg})
