from __future__ import annotations

import os
import platform
import sys
import time

from fastapi import APIRouter

from app import config

router = APIRouter(tags=["health"])


def _boolenv(name: str) -> bool:
    value = os.getenv(name, "")
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@router.get("/version")
def version() -> dict[str, object]:
    return {
        "version": os.getenv("APP_VERSION", config.APP_VERSION),
        "git_sha": os.getenv("GIT_SHA", config.GIT_SHA),
        "build_ts": os.getenv("BUILD_TS", config.BUILD_TS),
        "runtime": {
            "python": sys.version.split(" ")[0],
            "platform": platform.platform(),
            "tz": time.tzname,
        },
        "features": {
            "admin_auth_mode": os.getenv("ADMIN_AUTH_MODE", "cookie"),
            "rbac_default_role": os.getenv("ADMIN_RBAC_DEFAULT_ROLE", "viewer"),
            "audit_backend": os.getenv("AUDIT_BACKEND", "")
            or ("file" if config.AUDIT_LOG_FILE else "memory"),
            "mitigation_backend": os.getenv("MITIGATION_STORE_BACKEND", "")
            or (
                "file"
                if os.getenv("MITIGATION_STORE_FILE")
                else ("redis" if os.getenv("REDIS_URL") else "memory")
            ),
            "redis_url_set": bool(os.getenv("REDIS_URL", "")),
            "apply_golden_enabled": _boolenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK"),
            "force_block": _boolenv("FORCE_BLOCK"),
        },
    }
