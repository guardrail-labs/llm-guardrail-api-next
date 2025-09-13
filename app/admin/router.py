# app/admin/router.py
# Summary (PR-H fix 2):
# - Move HTML bindings view to /admin/bindings/ui to avoid path collision with
#   an existing JSON route at /admin/bindings.
# - Keeps POST /admin/bindings/apply unchanged.
# - JSON serialization fix retained for issues payload.

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.bindings.models import Binding
from app.services.bindings.repository import APPLY_ENABLED, get_bindings, set_bindings
from app.services.bindings.validator import (
    BindingIssue,
    choose_binding_for,
    validate_bindings,
)

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
async def admin_index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "admin/index.html", {"request": request, "apply_enabled": APPLY_ENABLED()}
    )


@router.get("/bindings/ui", response_class=HTMLResponse)
async def admin_bindings_ui(request: Request) -> HTMLResponse:
    bindings = get_bindings()
    issues = validate_bindings(bindings)
    return templates.TemplateResponse(
        "admin/bindings.html",
        {
            "request": request,
            "bindings": bindings,
            "issues": issues,
            "apply_enabled": APPLY_ENABLED(),
        },
    )


@router.post("/bindings/apply", response_class=JSONResponse)
async def admin_bindings_apply(payload: Dict[str, Any]) -> JSONResponse:
    """
    Accepts JSON payload:
      {"bindings": [{"tenant_id": "...", "bot_id": "...", "policy_version": "...",
                     "priority": 0, "model": null, "source": null}, ...]}
    """
    raw = payload.get("bindings") or []
    new_bindings: List[Binding] = []
    for item in raw:
        new_bindings.append(
            Binding(
                tenant_id=str(item.get("tenant_id", "")).strip() or "*",
                bot_id=str(item.get("bot_id", "")).strip() or "*",
                policy_version=str(item.get("policy_version", "")).strip(),
                model=(item.get("model") if item.get("model") else None),
                priority=int(item.get("priority") or 0),
                source=(item.get("source") if item.get("source") else None),
            )
        )
    issues: List[BindingIssue] = validate_bindings(new_bindings)
    applied = False
    if APPLY_ENABLED():
        set_bindings(new_bindings)
        applied = True
    issues_json = [asdict(i) for i in issues]
    return JSONResponse(
        {
            "applied": applied,
            "apply_enabled": APPLY_ENABLED(),
            "issues": issues_json,
            "count": len(new_bindings),
        }
    )


@router.get("/active-policy", response_class=HTMLResponse)
async def admin_active_policy(
    request: Request, tenant: Optional[str] = None, bot: Optional[str] = None
) -> HTMLResponse:
    t = (tenant or "*").strip() or "*"
    b = (bot or "*").strip() or "*"
    bindings = get_bindings()
    selected, candidates = choose_binding_for(bindings, t, b)
    return templates.TemplateResponse(
        "admin/active_policy.html",
        {
            "request": request,
            "tenant": t,
            "bot": b,
            "selected": selected,
            "candidates": candidates,
            "apply_enabled": APPLY_ENABLED(),
        },
    )


@router.get("/metrics")
async def admin_metrics() -> RedirectResponse:
    return RedirectResponse(url="/metrics", status_code=307)
