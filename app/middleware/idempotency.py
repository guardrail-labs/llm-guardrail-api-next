from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, MutableMapping, Tuple, cast

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.middleware.request_id import get_request_id
from app.observability.metrics import (
    idempotency_conflict,
    idempotency_replayed,
    idempotency_seen,
    idempotency_skipped,
)
from app.services.config_store import get_config
from app.services.idempotency_store import IdemStore, body_hash

try:  # pragma: no cover - optional dependency path
    from app.observability.metrics import _limit_tenant_bot_labels
except Exception:  # pragma: no cover

    def _limit_tenant_bot_labels(tenant: str, bot: str) -> tuple[str, str]:
        return (tenant[:32], bot[:32])


_KEY_RE = re.compile(r"^[A-Za-z0-9._\-:/]{1,200}$")
_STORE = IdemStore()


def _tenant_bot(req: Request) -> tuple[str, str]:
    tenant = req.headers.get("X-Guardrail-Tenant", "") or ""
    bot = req.headers.get("X-Guardrail-Bot", "") or ""
    return _limit_tenant_bot_labels(tenant, bot)


def _reinject_body(body: bytes) -> Receive:
    sent = {"done": False}

    async def _receive() -> Dict[str, Any]:
        if sent["done"]:
            return {"type": "http.request"}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return _receive


class IdempotencyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        cfg: Dict[str, Any] = dict(get_config())
        if not cfg.get("idempotency_enabled", True):
            await self.app(scope, receive, send)
            return

        method = (scope.get("method") or "").upper()
        methods_raw = cfg.get("idempotency_methods")
        if isinstance(methods_raw, str):
            methods_iter: Iterable[Any] = (
                part.strip() for part in methods_raw.split(",") if part.strip()
            )
        else:
            methods_iter = cast(Iterable[Any], methods_raw or [])
        allowed = {str(m).upper() for m in methods_iter}
        if not allowed:
            allowed = {"POST", "PUT", "PATCH", "DELETE"}
        if method not in allowed:
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")
        if not key:
            await self.app(scope, receive, send)
            return
        if not _KEY_RE.match(key):
            payload = {
                "code": "bad_request",
                "detail": "invalid idempotency key",
                "request_id": get_request_id() or "",
            }
            response = JSONResponse(payload, status_code=400)
            response.headers["X-Request-ID"] = payload["request_id"]
            response.headers["X-Idempotency-Status"] = "invalid"
            response.headers["Idempotency-Key"] = key
            response.headers["Idempotency-Replayed"] = "false"
            await response(scope, receive, send)
            return

        tenant, bot = _tenant_bot(request)
        idempotency_seen.labels(tenant=tenant, bot=bot, method=method).inc()

        max_body = int(cfg.get("idempotency_body_max_bytes", 131072) or 0)
        raw_body = await request.body()
        if max_body and len(raw_body) > max_body:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="size").inc()

            async def _send_skip(message: MutableMapping[str, Any]) -> None:
                if message.get("type") == "http.response.start":
                    headers = message.setdefault("headers", [])
                    headers.append((b"Idempotency-Key", key.encode("utf-8")))
                    headers.append((b"X-Idempotency-Status", b"skipped:size"))
                    headers.append((b"Idempotency-Replayed", b"false"))
                await send(message)

            await self.app(scope, _reinject_body(raw_body), _send_skip)
            return

        path = scope.get("path") or ""
        fingerprint = "|".join([method, path, tenant, bot, body_hash(raw_body)])

        ttl = int(cfg.get("idempotency_ttl_seconds", 86400) or 0)
        retry_after = int(cfg.get("idempotency_in_progress_retry_after", 1) or 1)

        record = await _STORE.get(key)
        if record:
            if record.state == "in_progress":
                idempotency_conflict.labels(tenant=tenant, bot=bot, reason="in_progress").inc()
                response = PlainTextResponse("Idempotency in progress", status_code=409)
                response.headers["Retry-After"] = str(retry_after)
                response.headers["X-Idempotency-Status"] = "in_progress"
                response.headers["Idempotency-Key"] = key
                response.headers["Idempotency-Replayed"] = "false"
                await response(scope, receive, send)
                return
            if record.fp != fingerprint:
                idempotency_conflict.labels(
                    tenant=tenant, bot=bot, reason="fingerprint_mismatch"
                ).inc()
                response = PlainTextResponse("Idempotency conflict", status_code=409)
                response.headers["X-Idempotency-Status"] = "conflict"
                response.headers["Idempotency-Key"] = key
                response.headers["Idempotency-Replayed"] = "false"
                await response(scope, receive, send)
                return

            idempotency_replayed.labels(tenant=tenant, bot=bot, method=method).inc()
            base_headers = {k: v for k, v in record.headers}
            headers = {
                **base_headers,
                "Content-Type": record.ctype
                or base_headers.get("Content-Type", "application/octet-stream"),
                "X-Idempotency-Status": "replayed",
                "Idempotency-Key": key,
                "Idempotency-Replayed": "true",
            }
            await Response(record.body, record.status, headers=headers)(scope, receive, send)
            return

        await _STORE.put_in_progress(key, fingerprint, ttl)

        captured_start: MutableMapping[str, Any] | None = None
        start_sent = False
        buffer = bytearray()
        is_streaming = False
        status_holder = {"status": 200}
        ctype_holder = {"ctype": ""}
        stored_headers_holder: Dict[str, List[Tuple[str, str]]] = {"headers": []}

        def _inject_headers(start_message: MutableMapping[str, Any], tag: str) -> None:
            headers: List[Tuple[bytes, bytes]] = start_message.setdefault("headers", [])
            headers.append((b"Idempotency-Key", key.encode("utf-8")))
            headers.append((b"X-Idempotency-Status", tag.encode("utf-8")))
            headers.append((b"Idempotency-Replayed", b"false"))

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal captured_start, start_sent, is_streaming
            msg_type = message.get("type")
            if msg_type == "http.response.start":
                captured_start = {
                    "type": msg_type,
                    "status": int(message.get("status", 200)),
                    "headers": list(message.get("headers") or []),
                }
                status_holder["status"] = int(message.get("status", 200))
                try:
                    header_map = {
                        k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in captured_start["headers"]
                    }
                    ctype_holder["ctype"] = header_map.get("content-type", "")
                except Exception:
                    ctype_holder["ctype"] = ""
                return
            if msg_type == "http.response.body":
                if captured_start is None:
                    captured_start = {
                        "type": "http.response.start",
                        "status": int(status_holder["status"]),
                        "headers": [],
                    }
                body = message.get("body") or b""
                more = bool(message.get("more_body"))
                if more:
                    is_streaming = True
                if not start_sent:
                    if is_streaming:
                        _inject_headers(captured_start, "skipped:stream")
                    else:
                        tag = "stored"
                        if max_body and len(body) > max_body:
                            tag = "skipped:size"
                        _inject_headers(captured_start, tag)
                    stored_headers_holder["headers"] = [
                        (hk.decode("latin-1"), hv.decode("latin-1"))
                        for hk, hv in captured_start["headers"]
                    ]
                    await send(captured_start)
                    start_sent = True
                if not is_streaming:
                    buffer.extend(body)
                await send(message)
                return
            await send(message)

        try:
            await self.app(scope, _reinject_body(raw_body), send_wrapper)
        except Exception:
            await _STORE.clear(key)
            raise

        if is_streaming:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="stream").inc()
            await _STORE.clear(key)
            return
        if max_body and len(buffer) > max_body:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="size").inc()
            await _STORE.clear(key)
            return

        await _STORE.complete(
            key,
            int(status_holder["status"]),
            bytes(buffer),
            str(ctype_holder["ctype"] or ""),
            fingerprint,
            stored_headers_holder.get("headers", []),
            ttl,
        )
