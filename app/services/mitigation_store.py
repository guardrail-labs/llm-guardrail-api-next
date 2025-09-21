"""Durable mitigation-mode storage.

The store defaults to an in-memory map for tests.  When
``MITIGATION_STORE_BACKEND=file`` (or unset with ``MITIGATION_STORE_FILE``
provided) the data is persisted to a JSON file using atomic writes.  When
``MITIGATION_STORE_BACKEND=redis`` (or ``REDIS_URL`` is set) the store uses
Redis keys.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple, TypedDict


class Entry(TypedDict):
    tenant: str
    bot: str
    mode: str  # "block" | "clarify" | "redact"


_LOCK = threading.RLock()
# Backwards-compatible handle for legacy tests that imported the in-memory map.
_MEM_STORE: Dict[Tuple[str, str], str] = {}
_STORE = _MEM_STORE
_REDIS_CLIENT: Any | None = None
_REDIS_URL: str | None = None


def _key(tenant: str, bot: str) -> Tuple[str, str]:
    return (tenant or "").strip(), (bot or "").strip()


def _backend() -> str:
    return os.getenv("MITIGATION_STORE_BACKEND", "").strip().lower()


def _file_location() -> Optional[str]:
    backend = _backend()
    path = os.getenv("MITIGATION_STORE_FILE", "").strip()
    if backend in ("", "file"):
        return path or None
    return None


def _file_load(path: str) -> Dict[Tuple[str, str], str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

    out: Dict[Tuple[str, str], str] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if "|" in k:
                tenant, bot = k.split("|", 1)
                out[(tenant, bot)] = v
    return out


def _file_save(path: str, data: Dict[Tuple[str, str], str]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".mitigation_modes.", dir=directory)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            payload = {
                f"{tenant}|{bot}": mode
                for (tenant, bot), mode in data.items()
            }
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


def _redis_client() -> Any | None:
    backend = _backend()
    url = os.getenv("REDIS_URL", "").strip()
    if backend == "redis" or (backend == "" and url):
        return _ensure_redis_client(url or "redis://localhost:6379/0")
    return None


def _ensure_redis_client(url: str) -> Any | None:
    global _REDIS_CLIENT, _REDIS_URL
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


def _redis_key(tenant: str, bot: str) -> str:
    return f"guardrail:mitigation:{tenant}:{bot}"


def _norm_mode(mode: str) -> str:
    if mode not in ("block", "clarify", "redact"):
        raise ValueError("invalid mode")
    return mode


def get_mode(tenant: str, bot: str) -> Optional[str]:
    tenant, bot = _key(tenant, bot)
    client = _redis_client()
    path = _file_location()
    with _LOCK:
        if client is not None:
            try:
                value = client.get(_redis_key(tenant, bot))
                if isinstance(value, str) and value:
                    return value
            except Exception:
                pass
        if path:
            data = _file_load(path)
            return data.get((tenant, bot))
        return _MEM_STORE.get((tenant, bot))


def set_mode(tenant: str, bot: str, mode: str) -> None:
    tenant, bot = _key(tenant, bot)
    mode = _norm_mode(mode)
    client = _redis_client()
    path = _file_location()
    with _LOCK:
        if client is not None:
            try:
                client.set(_redis_key(tenant, bot), mode)
                return
            except Exception:
                pass
        if path:
            data = _file_load(path)
            data[(tenant, bot)] = mode
            _file_save(path, data)
            return
        _MEM_STORE[(tenant, bot)] = mode


def clear_mode(tenant: str, bot: str) -> None:
    tenant, bot = _key(tenant, bot)
    client = _redis_client()
    path = _file_location()
    with _LOCK:
        if client is not None:
            try:
                client.delete(_redis_key(tenant, bot))
            except Exception:
                pass
        if path:
            data = _file_load(path)
            if (tenant, bot) in data:
                data.pop((tenant, bot), None)
                _file_save(path, data)
            return
        _MEM_STORE.pop((tenant, bot), None)


def list_modes() -> List[Entry]:
    client = _redis_client()
    path = _file_location()
    with _LOCK:
        if client is not None:
            try:
                items: Dict[Tuple[str, str], str] = {}
                cursor = "0"
                pattern = "guardrail:mitigation:*"
                while True:
                    cursor, keys = client.scan(cursor=cursor, match=pattern, count=500)
                    if keys:
                        values = client.mget(keys)
                        for key, value in zip(keys, values):
                            if not value:
                                continue
                            parts = key.split(":", 3)
                            if len(parts) == 4:
                                _, _, tenant, bot = parts
                                items[(tenant, bot)] = value
                    if cursor == "0":
                        break
                return [
                    {"tenant": tenant, "bot": bot, "mode": mode}
                    for (tenant, bot), mode in sorted(items.items())
                ]
            except Exception:
                pass
        if path:
            data = _file_load(path)
            return [
                {"tenant": tenant, "bot": bot, "mode": mode}
                for (tenant, bot), mode in sorted(data.items())
            ]
        return [
            {"tenant": tenant, "bot": bot, "mode": mode}
            for (tenant, bot), mode in sorted(_MEM_STORE.items())
        ]


def reset_for_tests() -> None:
    global _REDIS_CLIENT, _REDIS_URL
    path = _file_location()
    with _LOCK:
        _MEM_STORE.clear()
        _REDIS_CLIENT = None
        _REDIS_URL = None
        if path:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except Exception:
                pass
        client = _redis_client()
        if client is not None:
            try:
                cursor = "0"
                pattern = "guardrail:mitigation:*"
                while True:
                    cursor, keys = client.scan(cursor=cursor, match=pattern, count=500)
                    if keys:
                        client.delete(*keys)
                    if cursor == "0":
                        break
            except Exception:
                pass

