from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, Optional, cast

from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse

from app.middleware.request_id import get_request_id


@dataclass
class _CachedResponse:
    status: int
    body: bytes
    headers: Dict[str, str]


class _InMemoryStore:
    def __init__(self) -> None:
        self._data: Dict[str, tuple[float, _CachedResponse]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[_CachedResponse]:
        now = time.time()
        with self._lock:
            record = self._data.get(key)
            if not record:
                return None
            expires_at, cached = record
            if expires_at <= now:
                self._data.pop(key, None)
                return None
            return cached

    def set(self, key: str, value: _CachedResponse, ttl: int) -> None:
        expires_at = time.time() + max(ttl, 1)
        with self._lock:
            self._data[key] = (expires_at, value)


RequestHandler = Callable[[Request], Awaitable[StarletteResponse]]


class _RedisStore:
    def __init__(self, url: str, ttl: int) -> None:
        import redis

        self._cli = redis.from_url(url)
        self._ttl = max(ttl, 1)

    def get(self, key: str) -> Optional[_CachedResponse]:
        try:
            raw = self._cli.get(key)
        except Exception:
            return None
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
            body = base64.b64decode(parsed.get("body") or b"")
            headers = parsed.get("headers") or {}
            status = int(parsed.get("status") or 200)
            if not isinstance(headers, dict):
                headers = {}
            return _CachedResponse(status=status, body=body, headers=headers)
        except Exception:
            return None

    def set(self, key: str, value: _CachedResponse, ttl: int) -> None:
        payload = {
            "status": value.status,
            "body": base64.b64encode(value.body).decode("ascii"),
            "headers": value.headers,
        }
        try:
            self._cli.setex(key, max(ttl, 1), json.dumps(payload))
        except Exception:
            pass


def _error_response(detail: str) -> JSONResponse:
    payload = {
        "code": "bad_request",
        "detail": detail,
        "request_id": get_request_id() or "",
    }
    headers = {"X-Request-ID": payload["request_id"]}
    return JSONResponse(payload, status_code=400, headers=headers)


def _hash_body(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _tenant_from(request: Request) -> str:
    headers = request.headers
    tenant = (
        headers.get("X-Tenant-ID")
        or headers.get("X-Tenant-Id")
        or headers.get("X-Tenant")
        or getattr(request.state, "tenant", "")
    )
    return str(tenant or "")


def _bot_from(request: Request) -> str:
    headers = request.headers
    bot = (
        headers.get("X-Bot-ID")
        or headers.get("X-Bot-Id")
        or headers.get("X-Bot")
        or getattr(request.state, "bot", "")
    )
    return str(bot or "")


def _eligible_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    if normalized.startswith("/v1/batch/"):
        return True
    return normalized in {"/v1/guardrail"}


def _preserved_headers(source: Iterable[tuple[str, str]]) -> Dict[str, str]:
    keep = {
        "content-type",
        "x-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
    out: Dict[str, str] = {}
    for key, value in source:
        if key.lower() in keep:
            out[key] = value
    return out


_STORE_SINGLETON: _InMemoryStore | _RedisStore | None = None


def _load_store(ttl: int):
    global _STORE_SINGLETON
    if _STORE_SINGLETON is not None:
        return _STORE_SINGLETON
    url = os.getenv("IDEMPOTENCY_REDIS_URL") or os.getenv("REDIS_URL")
    if not url:
        _STORE_SINGLETON = _InMemoryStore()
        return _STORE_SINGLETON
    try:
        _STORE_SINGLETON = _RedisStore(url, ttl)
        return _STORE_SINGLETON
    except Exception:
        _STORE_SINGLETON = _InMemoryStore()
        return _STORE_SINGLETON


class IdempotencyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:
        super().__init__(app)
        ttl_raw = os.getenv("IDEMPOTENCY_TTL_SECONDS", "")
        try:
            ttl = int(ttl_raw)
        except Exception:
            ttl = 86400
        if ttl <= 0:
            ttl = 86400
        self._ttl = ttl
        self._store = _load_store(ttl)

    async def dispatch(
        self, request: Request, call_next: RequestHandler
    ) -> StarletteResponse:
        if request.method.upper() != "POST":
            return await call_next(request)
        path = request.url.path
        if not _eligible_path(path):
            return await call_next(request)

        key = request.headers.get("X-Idempotency-Key")
        if not key:
            return await call_next(request)
        if len(key) > 200:
            return _error_response("invalid idempotency key")

        body = await request.body()
        fingerprint = self._fingerprint(request, key, body)
        cached = self._store.get(fingerprint)
        if cached is not None:
            headers = dict(cached.headers)
            headers["Idempotency-Replayed"] = "true"
            return Response(content=cached.body, status_code=cached.status, headers=headers)

        response = await call_next(request)
        if "Idempotency-Replayed" not in response.headers:
            response.headers["Idempotency-Replayed"] = "false"
        status = getattr(response, "status_code", 200)
        if status >= 500:
            return response

        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is not None:
            content_length = response.headers.get("content-length")
            if content_length is None:
                return response
            chunks: list[bytes] = []
            iterator = cast(AsyncIterator[Any], body_iterator)

            async def _collect() -> None:
                async for chunk in iterator:
                    if isinstance(chunk, (bytes, bytearray)):
                        chunks.append(bytes(chunk))
                    elif isinstance(chunk, str):
                        chunks.append(chunk.encode("utf-8"))
                    else:
                        chunks.append(bytes(chunk))

            await _collect()

            async def _aiter():
                for chunk in chunks:
                    yield chunk

            setattr(response, "body_iterator", _aiter())
            body_bytes = b"".join(chunks)
        else:
            body_bytes = getattr(response, "body", b"")
            if not isinstance(body_bytes, (bytes, bytearray)):
                try:
                    body_bytes = bytes(body_bytes)
                except Exception:
                    body_bytes = b""

        headers = _preserved_headers(response.headers.items())
        headers.setdefault("Idempotency-Replayed", "false")
        cached_record = _CachedResponse(
            status=status,
            body=bytes(body_bytes),
            headers=headers,
        )
        self._store.set(fingerprint, cached_record, self._ttl)

        for name, value in headers.items():
            response.headers[name] = value
        return response

    def _fingerprint(self, request: Request, key: str, body: bytes) -> str:
        method = request.method.upper()
        path = request.url.path.rstrip("/") or "/"
        tenant = _tenant_from(request)
        bot = _bot_from(request)
        body_hash = _hash_body(body or b"")
        parts = ["idem", method, path, tenant, bot, body_hash, key]
        joined = ":".join(parts)
        digest = hashlib.sha256(joined.encode("utf-8", errors="ignore")).hexdigest()
        return f"idem:{digest}"
