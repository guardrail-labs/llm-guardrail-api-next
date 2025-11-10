from __future__ import annotations

import json
from collections import deque
from hmac import compare_digest
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.routes.admin_ui import _csrf_ok, require_auth
from app.services.config_store import get_config_audit_path, set_config

router = APIRouter(prefix="/admin", tags=["admin-config"])


def _read_audit(max_rows: int) -> List[Dict[str, Any]]:
    path = get_config_audit_path()
    if not path.exists():
        return []
    rows: deque[Dict[str, Any]] = deque(maxlen=max_rows if max_rows > 0 else None)
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    rows.append(parsed)
    except Exception:
        return []
    return list(rows)


def _csrf_ok_equal(request: Request, token: Optional[str]) -> None:
    cookie = request.cookies.get("ui_csrf", "")
    if not (
        cookie and token and _csrf_ok(cookie) and _csrf_ok(token) and compare_digest(cookie, token)
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF failed")


@router.get("/config/versions")
def list_versions(limit: int = 100, _: None = Depends(require_auth)) -> JSONResponse:
    limit = max(1, min(500, int(limit)))
    rows = _read_audit(limit)

    def diff_keys(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
        keys = set(a.keys()) | set(b.keys())
        out: List[str] = []
        for key in keys:
            if a.get(key) != b.get(key):
                out.append(str(key))
        return sorted(out)

    prepared: List[Dict[str, Any]] = []
    for row in rows:
        before = row.get("before")
        after = row.get("after")
        before_dict = before if isinstance(before, dict) else {}
        after_dict = after if isinstance(after, dict) else {}
        prepared.append(
            {
                "ts": row.get("ts"),
                "actor": row.get("actor"),
                "changed_keys": diff_keys(before_dict, after_dict),
                "before": before_dict,
                "after": after_dict,
            }
        )
    return JSONResponse(list(reversed(prepared)))


@router.post("/config/rollback")
async def rollback_config(request: Request, _: None = Depends(require_auth)) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid json")

    if not isinstance(body, dict) or "ts" not in body:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload")

    token = body.get("csrf_token") or request.headers.get("x-csrf-token")
    _csrf_ok_equal(request, token if isinstance(token, str) else None)

    try:
        target_ts = int(body["ts"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload")

    rows = _read_audit(10000)
    entry: Optional[Dict[str, Any]] = None
    for candidate in rows:
        try:
            if int(candidate.get("ts", -1)) == target_ts:
                entry = candidate
                break
        except Exception:
            continue

    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    before = entry.get("before")
    if not isinstance(before, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid audit entry")

    new_cfg = set_config(before, actor="admin-rollback", replace=True)
    return JSONResponse(new_cfg, status_code=status.HTTP_200_OK)
