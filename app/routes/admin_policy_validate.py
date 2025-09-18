from __future__ import annotations

import importlib
import os

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

router = APIRouter()


def _load_require_admin():
    for mod_name, fn_name in (
        ("app.routes.admin_rbac", "require_admin"),
        ("app.security.admin_auth", "require_admin"),
        ("app.routes.admin_common", "require_admin"),
    ):
        try:
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                return fn
        except Exception:  # pragma: no cover - best effort fallback
            continue
    return None


def _require_admin_dep(request: Request):
    guard = _load_require_admin()
    if callable(guard):
        guard(request)
        return
    key = os.getenv("ADMIN_API_KEY") or os.getenv("GUARDRAIL_ADMIN_KEY")
    if key and (request.headers.get("X-Admin-Key") != key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@router.post("/admin/api/policy/validate", dependencies=[Depends(_require_admin_dep)])
async def policy_validate(payload: dict = Body(...)) -> JSONResponse:
    text = payload.get("yaml") or payload.get("text") or ""
    from app.services.policy_validate import validate_yaml_text

    result = validate_yaml_text(str(text))

    try:
        from prometheus_client import Counter  # pragma: no cover

        counter = Counter(
            "guardrail_policy_validate_total",
            "Policy validation runs by status",
            ["status"],
        )
        counter.labels(status=result["status"]).inc()
    except Exception:  # pragma: no cover - metrics optional
        pass

    status_code = (
        status.HTTP_200_OK
        if result["status"] == "ok"
        else status.HTTP_422_UNPROCESSABLE_ENTITY
    )
    return JSONResponse(result, status_code=status_code)
