from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple
from hmac import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import require_auth, _csrf_ok  # reuse existing auth + CSRF helpers
from app.services.config_store import get_config, set_config, normalize_patch

router = APIRouter(prefix="/admin", tags=["admin-config"])

# ---- Helpers ----------------------------------------------------------------

def _extract_csrf_token(request: Request, payload: Optional[Mapping[str, Any]]) -> Optional[str]:
    """
    Try to get a CSRF token from:
      1) Header: X-CSRF-Token
      2) JSON body: {"csrf_token": "..."} (if JSON)
      3) Form field: csrf_token (handled separately by form endpoint if you have one)
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
    if not (cookie and csrf_token and _csrf_ok(cookie) and _csrf_ok(csrf_token) and compare_digest(cookie, csrf_token)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF failed")


def _normalize_json_payload(payload: Mapping[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Use the config_store.normalize_patch to strictly coerce known keys/types.
    Also collect simple per-key errors for user feedback (optional).
    """
    try:
        patch = normalize_patch(payload)
    except Exception:
        patch = {}
    # For now, we don't produce granular errors — return empty dict.
    return patch, {}


# ---- Endpoints ---------------------------------------------------------------

@router.get("/config")
def get_cfg(_: None = Depends(require_auth)) -> JSONResponse:
    return JSONResponse(get_config())


@router.post("/config")
async def update_runtime_config(request: Request, _: None = Depends(require_auth)) -> JSONResponse:
    """
    Accept JSON or form POST to update runtime configuration, with CSRF equality check.
    - JSON: Content-Type: application/json; body contains keys and optional "csrf_token".
    - Form: application/x-www-form-urlencoded or multipart/form-data; we read `csrf_token` and fields from form.
    """
    content_type = (request.headers.get("content-type") or "").lower()

    # A) JSON path
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid json")

        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload")

        csrf_token = _extract_csrf_token(request, payload)
        _csrf_check_or_400(request, csrf_token)

        patch, _errors = _normalize_json_payload(payload)
        if patch:
            set_config(patch)
        return JSONResponse(get_config(), status_code=status.HTTP_200_OK)

    # B) Form path (fallback for existing UI posts)
    try:
        form = await request.form()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid form")

    csrf_token = (form.get("csrf_token") or "") if form else ""
    csrf_token = str(csrf_token) if csrf_token is not None else ""
    _csrf_check_or_400(request, csrf_token)

    # Map form fields to a dict, pass through normalizer
    form_dict: Dict[str, Any] = {}
    for k, v in (form or {}).items():
        if k == "csrf_token":
            continue
        form_dict[k] = v

    patch, _errors = _normalize_json_payload(form_dict)
    if patch:
        set_config(patch)
    return JSONResponse(get_config(), status_code=status.HTTP_200_OK)
