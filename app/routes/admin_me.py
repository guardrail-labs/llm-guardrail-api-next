from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.security import rbac

router = APIRouter(prefix="/admin/api", tags=["admin-auth"])


class MeResp(BaseModel):
    authenticated: bool
    email: str | None = None
    name: str | None = None
    role: str | None = None


@router.get("/me", response_model=MeResp)
def me(request: Request) -> MeResp:
    user = rbac.get_current_user(request)
    if not user:
        return MeResp(authenticated=False)
    return MeResp(
        authenticated=True,
        email=user.get("email"),
        name=user.get("name"),
        role=rbac.effective_role(user),
    )
