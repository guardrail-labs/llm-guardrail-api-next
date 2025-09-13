from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.security.admin_auth import require_admin
from app.services.rulepacks import list_rulepacks, load_rulepack

router = APIRouter(prefix="/admin/rulepacks", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("")
def rulepacks_index() -> JSONResponse:
    return JSONResponse({"available": list_rulepacks()})


@router.get("/{name}")
def rulepack_detail(name: str) -> JSONResponse:
    try:
        data: Dict[str, Any] = load_rulepack(name)
    except FileNotFoundError:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(data)
