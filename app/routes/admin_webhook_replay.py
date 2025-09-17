from __future__ import annotations

from hmac import compare_digest
from typing import Any, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_rbac import require_admin
from app.routes.admin_ui import _csrf_ok, require_auth
from app.services.webhooks import dlq_count, requeue_from_dlq

router = APIRouter(prefix="/admin", tags=["admin-webhook-replay"])


def _extract_csrf(req: Request, payload: Optional[Mapping[str, Any]]) -> Optional[str]:
    header = req.headers.get("x-csrf-token")
    if header:
        return header
    if payload and isinstance(payload, Mapping):
        token = payload.get("csrf_token")
        if isinstance(token, str) and token:
            return token
    return None


def _csrf_check(req: Request, token: Optional[str]) -> None:
    cookie = req.cookies.get("ui_csrf", "")
    ok = bool(
        cookie
        and token
        and _csrf_ok(cookie)
        and _csrf_ok(token)
        and compare_digest(cookie, token)
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF failed")


def _parse_limit(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value))
        except Exception:
            return None


@router.get("/webhook/dlq")
def get_dlq(_: None = Depends(require_auth)) -> JSONResponse:
    return JSONResponse({"count": dlq_count()})


@router.post("/webhook/replay")
async def post_replay(
    req: Request,
    _: None = Depends(require_auth),
    _admin: None = Depends(require_admin),
) -> JSONResponse:
    content_type = (req.headers.get("content-type") or "").lower()
    limit = 100
    token: Optional[str] = None

    if "application/json" in content_type:
        try:
            payload = await req.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid json")
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=400, detail="invalid payload")
        token = _extract_csrf(req, payload)
        parsed_limit = _parse_limit(payload.get("limit"))
        if parsed_limit is not None:
            limit = parsed_limit
    else:
        try:
            form = await req.form()
        except Exception:
            form = None
        if form is not None:
            token = _extract_csrf(req, form)
            parsed_limit = _parse_limit(form.get("limit") if hasattr(form, "get") else None)
            if parsed_limit is not None:
                limit = parsed_limit

    _csrf_check(req, token)
    requeued = requeue_from_dlq(limit)
    return JSONResponse({"requeued": requeued})
