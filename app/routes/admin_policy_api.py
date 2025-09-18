from __future__ import annotations

import yaml
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.routes.admin_rbac import require_admin
from app.services.config_store import get_policy_packs
from app.services.policy import current_rules_version, force_reload, get_pack_refs
from app.services.policy_packs import merge_packs
from app.services.policy_validate_enforce import validate_text_for_reload

router = APIRouter()


@router.get("/admin/api/policy/version")
def policy_version() -> JSONResponse:
    """
    Returns the active merged policy version and configured packs.
    """

    return JSONResponse(
        {
            "version": current_rules_version(),
            "packs": get_policy_packs(),
            "refs": get_pack_refs(),  # includes resolved file paths for diagnostics
        }
    )


def _csrf_check(request: Request, token_body: str | None) -> None:
    """
    Double-submit CSRF: cookie 'ui_csrf' must match token in body OR 'X-CSRF-Token' header.
    """

    cookie = (request.cookies.get("ui_csrf") or "").strip()
    header = (request.headers.get("X-CSRF-Token") or "").strip()
    body = (token_body or "").strip()
    if not cookie or (cookie != header and cookie != body):
        raise HTTPException(status_code=400, detail="CSRF failed")


@router.post("/admin/api/policy/reload")
def policy_reload(
    request: Request,
    payload: dict = Body(...),
    _admin: None = Depends(require_admin),
) -> JSONResponse:
    """
    Reload policy packs; returns the new version. CSRF-protected.
    Payload may include: {"csrf_token": "..."} for double-submit.
    """

    _csrf_check(request, str(payload.get("csrf_token", "")))
    pack_names = get_policy_packs()
    merged_policy, _, _ = merge_packs(pack_names)
    if isinstance(merged_policy, dict):
        merged_yaml_text = yaml.safe_dump(
            merged_policy, sort_keys=False, allow_unicode=True
        )
    else:
        merged_yaml_text = str(merged_policy or "")

    allow_apply, validation = validate_text_for_reload(merged_yaml_text)
    if not allow_apply:
        try:  # pragma: no cover - metrics optional
            from prometheus_client import Counter

            Counter(
                "guardrail_policy_reload_blocked_total",
                "Reload attempts blocked by validation",
                ["reason"],
            ).labels(reason="validation_error").inc()
        except Exception:  # pragma: no cover
            pass

        return JSONResponse(
            {"status": "fail", "validation": validation},
            status_code=422,
        )

    version = force_reload()
    payload = {
        "status": "ok",
        "validation": validation,
        "result": {"version": version},
        "version": version,
    }
    return JSONResponse(payload)
