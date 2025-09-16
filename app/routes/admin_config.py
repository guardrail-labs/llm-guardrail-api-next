from __future__ import annotations

from hmac import compare_digest
from typing import Any, Dict, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import _csrf_ok, require_auth
from app.services.config_store import get_config, set_config

router = APIRouter(prefix="/admin", tags=["admin-config"])


# ---- Helpers ----------------------------------------------------------------


def _extract_csrf_token(
    request: Request, payload: Optional[Mapping[str, Any]]
) -> Optional[str]:
    """
    Try to get a CSRF token from (in order):
      1) Header: X-CSRF-Token
      2) JSON body: {"csrf_token": "..."} (if JSON)
      3) Form body handled by the form branch in the endpoint
    """
    hdr = request.headers.get("x-csrf-token")
    if hdr:
        return hdr
    if payload and isinstance(payload, Mapping):
        tok = payload.get("csrf_token")
        if isinstance(tok, str) and tok:
            return tok
    return None


def _csrf_check_or_400(request: Request, csrf_token: Optional[str]) -> None:
    cookie = request.cookies.get("ui_csrf", "")
    ok = (
        cookie
        and csrf_token
        and _csrf_ok(cookie)
        and _csrf_ok(csrf_token)
        and compare_digest(cookie, csrf_token)
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF failed"
        )


# ---- Endpoints ---------------------------------------------------------------


@router.get("/config")
def get_cfg(_: None = Depends(require_auth)) -> JSONResponse:
    return JSONResponse(get_config())


@router.post("/config")
async def update_runtime_config(
    request: Request, _: None = Depends(require_auth)
) -> JSONResponse:
    """
    Accept JSON or form POST to update runtime configuration, with CSRF equality check.

    - JSON:
      Content-Type: application/json; body contains keys and optional "csrf_token".
    - Form:
      application/x-www-form-urlencoded or multipart/form-data; we read a "csrf_token"
      field and additional key/value fields to update.
    """
    content_type = (request.headers.get("content-type") or "").lower()

    # A) JSON path
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid json"
            )

        if not isinstance(payload, Mapping):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload"
            )

        csrf_token = _extract_csrf_token(request, payload)
        _csrf_check_or_400(request, csrf_token)

        # Hand off to config_store; it handles normalization/typing.
        set_config(dict(payload), actor="admin-ui")
        return JSONResponse(get_config(), status_code=status.HTTP_200_OK)

    # B) Form path (fallback for existing UI posts)
    try:
        form = await request.form()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid form"
        )

    csrf_token_val = (form.get("csrf_token") or "") if form else ""
    csrf_token = str(csrf_token_val) if csrf_token_val is not None else ""
    _csrf_check_or_400(request, csrf_token)

    # Map form fields to a dict; config_store will coerce/ignore as needed.
    form_dict: Dict[str, Any] = {}
    for k, v in (form or {}).items():
        if k == "csrf_token":
            continue
        form_dict[k] = v

    set_config(form_dict, actor="admin-ui")
    return JSONResponse(get_config(), status_code=status.HTTP_200_OK)
