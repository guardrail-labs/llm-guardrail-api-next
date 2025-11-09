"""Admin feature flag endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.config import get_settings
from app.routes.admin_mitigation import require_admin_session

router = APIRouter(prefix="/admin/api", tags=["admin-features"])


class FeaturesResp(BaseModel):
    golden_one_click: bool


@router.get("/features", response_model=FeaturesResp)
def get_features(_session: None = Depends(require_admin_session)) -> FeaturesResp:
    settings = get_settings()
    enabled = bool(getattr(settings, "ADMIN_ENABLE_GOLDEN_ONE_CLICK", False))
    return FeaturesResp(golden_one_click=enabled)
