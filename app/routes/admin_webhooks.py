from __future__ import annotations

import importlib
import inspect
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from app import settings
from app.runtime import get_redis
from app.webhooks.dlq import DeadLetterQueue
from app.webhooks.retry import RetryQueue


def _load_guard(path: str, default_name: str) -> Optional[Any]:
    module_name, _, fn_name = path.partition(":")
    fn_name = fn_name or default_name
    try:
        module = importlib.import_module(module_name)
    except Exception:  # pragma: no cover - best-effort shim
        return None
    guard = getattr(module, fn_name, None)
    return guard if callable(guard) else None


async def _maybe_call_guard(guard: Any, request: Request) -> None:
    try:
        result = guard(request)
        if inspect.isawaitable(result):
            await result
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - guard blew up
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR) from exc


async def _require_admin_dep(request: Request) -> None:
    guard = _load_guard(
        os.getenv("ADMIN_GUARD", "app.routes.admin_rbac:require_admin"),
        "require_admin",
    ) or _load_guard("app.security.admin_auth:require_admin", "require_admin")
    if callable(guard):
        await _maybe_call_guard(guard, request)
        return

    cfg_key = (
        os.getenv("ADMIN_API_KEY")
        or os.getenv("GUARDRAIL_ADMIN_KEY")
        or getattr(
            getattr(getattr(request.app.state, "settings", None), "admin", None),
            "key",
            None,
        )
    )
    if not cfg_key:
        return

    supplied = request.headers.get("X-Admin-Key") or request.query_params.get("admin_key")
    if str(supplied) != str(cfg_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required"
        )


async def _require_csrf_dep(request: Request) -> None:
    guard = _load_guard(
        os.getenv("ADMIN_CSRF_GUARD", "app.routes.admin_common:require_csrf"),
        "require_csrf",
    ) or _load_guard("app.security.admin_auth:require_csrf", "require_csrf")
    if callable(guard):
        result = guard(request)
        if inspect.isawaitable(result):
            await result
        return

    token = request.headers.get("X-CSRF-Token") or request.query_params.get("csrf")
    if not token:
        try:
            form = await request.form()
            raw = form.get("csrf") or form.get("csrf_token")
            token = str(raw) if raw is not None else None
        except Exception:  # pragma: no cover - malformed body
            token = None

    cookie = (
        request.cookies.get("admin_csrf")
        or request.cookies.get("XSRF-TOKEN")
        or request.cookies.get("csrf")
        or request.cookies.get("csrf_token")
    )

    if not token or not cookie or str(token) != str(cookie):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CSRF token",
        )


router = APIRouter(dependencies=[Depends(_require_admin_dep)])


def _svc():
    for name in ("app.services.webhooks", "app.services.webhook"):
        try:
            return importlib.import_module(name)
        except Exception:
            continue
    raise HTTPException(status_code=501, detail="webhooks service not available")


@router.get("/admin/api/webhooks/status")
async def webhooks_status(
    request: Request,
    peek: int = Query(0, ge=0, le=100),
) -> JSONResponse:
    svc = _svc()

    dlq_len: Optional[int]
    try:
        if hasattr(svc, "dlq_size"):
            dlq_len = int(svc.dlq_size())
        elif hasattr(svc, "dlq_len"):
            dlq_len = int(svc.dlq_len())
        else:
            dlq_len = None
    except Exception:
        dlq_len = None

    breaker: dict[str, Any] = {}
    try:
        if hasattr(svc, "breaker_snapshot"):
            snap = svc.breaker_snapshot()
            if isinstance(snap, dict):
                breaker = snap
    except Exception:
        breaker = {}

    sample: list[Any] = []
    if peek and hasattr(svc, "dlq_peek"):
        try:
            peeked = svc.dlq_peek(peek)
            if isinstance(peeked, list):
                sample = peeked
        except Exception:
            sample = []

    payload = {
        "status": "ok",
        "dlq": {"length": dlq_len, "peek": sample},
        "breaker": breaker,
        "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    resp = JSONResponse(payload)

    if not request.cookies.get("admin_csrf"):
        token = secrets.token_urlsafe(32)
        resp.set_cookie(
            key="admin_csrf",
            value=token,
            path="/",
            secure=True,
            httponly=False,
            samesite="strict",
            max_age=3600,
        )
    return resp


_REPLAY_LOCK = threading.Lock()
_LAST_REPLAY_AT: float = 0.0


@router.post("/admin/api/webhooks/replay", dependencies=[Depends(_require_csrf_dep)])
async def webhooks_replay(
    request: Request,
    max_batch: int = Form(
        100,
        ge=1,
        le=int(os.getenv("WEBHOOK_REPLAY_MAX_BATCH", "1000")),
    ),
    since_seconds: Optional[int] = Form(None),
    dry_run: bool = Form(False),
) -> JSONResponse:
    svc = _svc()

    limit_cfg = int(os.getenv("WEBHOOK_REPLAY_MAX_BATCH", "1000"))
    window_cfg = int(os.getenv("WEBHOOK_REPLAY_MAX_WINDOW_SEC", "86400"))
    cooldown = int(os.getenv("WEBHOOK_REPLAY_COOLDOWN_SEC", "10"))

    global _LAST_REPLAY_AT
    now = time.time()
    if now - _LAST_REPLAY_AT < cooldown:
        raise HTTPException(status_code=429, detail=f"Replay cooldown active ({cooldown}s)")

    if max_batch > limit_cfg:
        raise HTTPException(status_code=400, detail=f"max_batch exceeds limit {limit_cfg}")

    if since_seconds is not None and since_seconds > window_cfg:
        raise HTTPException(status_code=400, detail=f"since_seconds exceeds window {window_cfg}")

    if not _REPLAY_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Replay already in progress")

    try:
        if dry_run and hasattr(svc, "dlq_peek"):
            try:
                sample_size = min(
                    max_batch,
                    int(os.getenv("WEBHOOK_REPLAY_DRYRUN_SAMPLE", "50")),
                )
            except ValueError:
                sample_size = min(max_batch, 50)
            peeked = svc.dlq_peek(sample_size) if hasattr(svc, "dlq_peek") else []
            sample_count = len(peeked or []) if isinstance(peeked, list) else 0
            return JSONResponse({"status": "dry-run", "sample_count": sample_count})

        if hasattr(svc, "replay_dlq"):
            replayed = int(svc.replay_dlq(max_batch=max_batch, since_seconds=since_seconds))
        elif hasattr(svc, "replay"):
            replayed = int(svc.replay(limit=max_batch, since_seconds=since_seconds))
        else:
            raise HTTPException(status_code=501, detail="Replay not supported by service")

        _LAST_REPLAY_AT = time.time()
        return JSONResponse({"status": "ok", "replayed": replayed, "cooldown_sec": cooldown})
    finally:
        _REPLAY_LOCK.release()


@router.get("/admin/webhooks/dlq/peek")
async def admin_webhooks_dlq_peek(
    limit: int = Query(20, ge=1, le=200),
) -> List[Dict[str, Any]]:
    redis = get_redis()
    dlq = DeadLetterQueue(redis, prefix=settings.WH_REDIS_PREFIX)
    items = await dlq.peek(limit)
    return [
        {
            "url": job.url,
            "method": job.method,
            "attempt": job.attempt,
            "created_at_s": job.created_at_s,
            "last_error": job.last_error,
        }
        for job in items
    ]


@router.post(
    "/admin/webhooks/dlq/replay",
    dependencies=[Depends(_require_csrf_dep)],
)
async def admin_webhooks_dlq_replay(
    limit: int = Query(50, ge=1, le=1000),
) -> Dict[str, int]:
    redis = get_redis()
    dlq = DeadLetterQueue(redis, prefix=settings.WH_REDIS_PREFIX)
    retry_queue = RetryQueue(redis, prefix=settings.WH_REDIS_PREFIX)
    moved = await dlq.replay_to(retry_queue, limit=limit, now_s=time.time())
    return {"replayed": moved}


@router.delete(
    "/admin/webhooks/dlq/purge",
    dependencies=[Depends(_require_csrf_dep)],
)
async def admin_webhooks_dlq_purge(
    older_than_s: float = Query(..., gt=0.0),
) -> Dict[str, int]:
    redis = get_redis()
    dlq = DeadLetterQueue(redis, prefix=settings.WH_REDIS_PREFIX)
    removed = await dlq.purge_older_than(older_than_s)
    return {"removed": removed}
