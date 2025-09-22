from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from app import config

_log = logging.getLogger("admin_audit")

_LOG_LOCK = threading.RLock()
_RING: List[Dict[str, Any]] = []
_RING_MAX = 500
_REDIS_CLIENT: Any | None = None
_REDIS_URL: str | None = None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _storage_mode() -> str:
    backend = (getattr(config, "AUDIT_BACKEND", "") or "").strip().lower()
    if backend == "redis":
        return "redis"
    if backend == "memory":
        return "memory"
    if backend == "file" or getattr(config, "AUDIT_LOG_FILE", ""):
        return "file"
    return "memory"


def _persist_file_line(line: str) -> None:
    path = getattr(config, "AUDIT_LOG_FILE", "")
    if not path:
        return
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
    except Exception:
        pass


def _iter_file_lines() -> List[str]:
    path = getattr(config, "AUDIT_LOG_FILE", "")
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]
    except Exception:
        return []


def _redis_client() -> Any | None:
    global _REDIS_CLIENT, _REDIS_URL
    url = (os.getenv("REDIS_URL", "").strip() or "redis://localhost:6379/0")
    if _REDIS_CLIENT is not None and _REDIS_URL == url:
        return _REDIS_CLIENT
    try:
        import redis

        client = redis.Redis.from_url(url, decode_responses=True)
    except Exception:
        _REDIS_CLIENT = None
        _REDIS_URL = None
        return None

    _REDIS_CLIENT = client
    _REDIS_URL = url
    return client


def _persist_redis_line(line: str) -> None:
    client = _redis_client()
    if client is None:
        return
    redis_key = getattr(config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1")
    maxlen = getattr(config, "AUDIT_REDIS_MAXLEN", 50000)
    try:
        pipe = client.pipeline()
        pipe.rpush(redis_key, line)
        pipe.ltrim(redis_key, -maxlen, -1)
        pipe.execute()
    except Exception:
        pass


def record(
    *,
    action: str,
    actor_email: Optional[str],
    actor_role: Optional[str],
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    outcome: str = "ok",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evt = {
        "ts_ms": _now_ms(),
        "action": action,
        "actor_email": actor_email,
        "actor_role": actor_role,
        "tenant": tenant,
        "bot": bot,
        "outcome": outcome,
        "meta": meta or {},
    }
    try:
        _log.info(json.dumps(evt, separators=(",", ":"), ensure_ascii=False))
    except Exception:
        pass

    line = json.dumps(evt, separators=(",", ":"), ensure_ascii=False)
    mode = _storage_mode()
    with _LOG_LOCK:
        _RING.append(evt)
        if len(_RING) > _RING_MAX:
            del _RING[: len(_RING) - _RING_MAX]
    if mode == "file":
        _persist_file_line(line)
    elif mode == "redis":
        _persist_redis_line(line)
    return evt


def _recent_from_file(cap: int) -> List[Dict[str, Any]]:
    lines = _iter_file_lines()
    items: List[Dict[str, Any]] = []
    for raw in lines[-cap:]:
        try:
            items.append(json.loads(raw))
        except Exception:
            continue
    return items


def _recent_from_redis(cap: int) -> List[Dict[str, Any]]:
    client = _redis_client()
    if client is None:
        return []
    try:
        redis_key = getattr(config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1")
        values = client.lrange(redis_key, -cap, -1)
    except Exception:
        return []
    items: List[Dict[str, Any]] = []
    for raw in values:
        try:
            items.append(json.loads(raw))
        except Exception:
            continue
    return items


def recent(limit: int = 50) -> List[Dict[str, Any]]:
    max_recent = getattr(config, "AUDIT_RECENT_LIMIT", _RING_MAX) or _RING_MAX
    cap = max(1, min(limit, max_recent))
    mode = _storage_mode()
    if mode == "file":
        items = _recent_from_file(cap)
        if items:
            return items
    elif mode == "redis":
        items = _recent_from_redis(cap)
        if items:
            return items
    with _LOG_LOCK:
        return list(_RING[-cap:])


def iter_events(
    *,
    since: Optional[int] = None,
    until: Optional[int] = None,
    tenant: Optional[str] = None,
    bot: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
) -> Iterable[Dict[str, Any]]:
    def _match(obj: Dict[str, Any]) -> bool:
        try:
            ts = int(obj.get("ts_ms", 0))
        except Exception:
            return False
        if since is not None and ts < since:
            return False
        if until is not None and ts > until:
            return False
        if tenant and obj.get("tenant") != tenant:
            return False
        if bot and obj.get("bot") != bot:
            return False
        if action and obj.get("action") != action:
            return False
        if outcome and obj.get("outcome") != outcome:
            return False
        return True

    yielded_any = False
    mode = _storage_mode()
    try:
        if mode == "file":
            for raw in _iter_file_lines():
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if _match(obj):
                    yielded_any = True
                    yield obj
        elif mode == "redis":
            client = _redis_client()
            if client is not None:
                try:
                    redis_key = getattr(config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1")
                    values = client.lrange(redis_key, 0, -1)
                except Exception:
                    values = []
                for raw in values:
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        continue
                    if _match(obj):
                        yielded_any = True
                        yield obj
    except Exception:
        pass

    if not yielded_any:
        with _LOG_LOCK:
            snapshot = list(_RING)
        for item in snapshot:
            if _match(item):
                yield item


def delete_where(
    *,
    tenant: Optional[str],
    bot: Optional[str],
    before_ts_ms: Optional[int],
) -> int:
    """Delete audit events that match the provided filters."""

    cutoff = int(before_ts_ms) if before_ts_ms is not None else None

    def _matches(obj: Dict[str, Any]) -> bool:
        try:
            ts = int(obj.get("ts_ms", 0))
        except Exception:
            ts = 0
        if tenant and obj.get("tenant") != tenant:
            return False
        if bot and obj.get("bot") != bot:
            return False
        if cutoff is not None and ts >= cutoff:
            return False
        return True

    deleted = 0
    mode = _storage_mode()
    if mode == "file":
        path = getattr(config, "AUDIT_LOG_FILE", "")
        lines = _iter_file_lines()
        kept_lines: List[str] = []
        for raw in lines:
            try:
                obj = json.loads(raw)
            except Exception:
                kept_lines.append(raw)
                continue
            if _matches(obj):
                deleted += 1
            else:
                kept_lines.append(raw)
        if path:
            tmp_path = f"{path}.tmp"
            try:
                with open(tmp_path, "w", encoding="utf-8") as handle:
                    for line in kept_lines:
                        handle.write(line + "\n")
                os.replace(tmp_path, path)
            except Exception:
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
    elif mode == "redis":
        client = _redis_client()
        if client is not None:
            redis_key = getattr(config, "AUDIT_REDIS_KEY", "guardrail:admin_audit:v1")
            kept_values: List[str] = []
            try:
                values = client.lrange(redis_key, 0, -1)
            except Exception:
                values = []
            for raw in values:
                try:
                    obj = json.loads(raw)
                except Exception:
                    kept_values.append(raw)
                    continue
                if _matches(obj):
                    deleted += 1
                else:
                    kept_values.append(raw)
            try:
                pipe = client.pipeline()
                pipe.delete(redis_key)
                if kept_values:
                    pipe.rpush(redis_key, *kept_values)
                pipe.execute()
            except Exception:
                pass
    else:
        with _LOG_LOCK:
            kept_ring: List[Dict[str, Any]] = []
            for obj in list(_RING):
                if _matches(obj):
                    deleted += 1
                else:
                    kept_ring.append(obj)
            _RING[:] = kept_ring
        return deleted

    with _LOG_LOCK:
        _RING[:] = [obj for obj in _RING if not _matches(obj)]
    return deleted


__all__ = [
    "iter_events",
    "delete_where",
    "record",
    "recent",
    "_iter_file_lines",
    "_persist_file_line",
    "_persist_redis_line",
    "_RING",
    "_RING_MAX",
    "_redis_client",
    "_storage_mode",
]
