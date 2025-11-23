from __future__ import annotations

from fastapi import Request

from app.routes.admin_rbac import require_admin as require_admin_rbac
from app.security.admin_auth import require_admin as require_admin_token


def AdminAuthDependency(request: Request) -> None:
    """
    Shared admin guard dependency combining token- and key-based checks.
    """

    require_admin_token(request)
    require_admin_rbac(request)


__all__ = ["AdminAuthDependency"]

