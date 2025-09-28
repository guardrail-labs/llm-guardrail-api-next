# app/middleware/idempotency.py
from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, MutableMapping, Tuple

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.observability.metrics import (
    idempotency_conflict,
    idempotency_replayed,
    idempotency_seen,
    idempotency_skipped,
)
from app.services.idempotency_store import IdemStore, body_hash


def _get_config() -> dict[str, Any]:
    """Runtime settings accessor that avoids static attr-defined issues."""
    settings = importlib.import_module("app.settings")
    cfg_fn = getattr(settings, "get_config", None)
    return dict(cfg_fn()) if callable(cfg_fn) else {}


try:
    from app.observability.metrics import _limit_tenant_bot_labels
except Exception:  # pragma: no cover
    def _limit_tenant_bot_labels(tenant: str, bot: str) -> tuple[str, str]:
        return (tenant[:32], bot[:32])


# Allowed chars, and hard limit of 200 chars (tests expect >200 to be 400)
_KEY_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")

_STORE: IdemStore = IdemStore()


def _tenant_bot(req: Request) -> tuple[str, str]:
    t = req.headers.get("X-Guardrail-Tenant", "") or ""
    b = req.headers.get("X-Guardrail-Bot", "") or ""
    return _limit_tenant_bot_labels(t, b)


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

        cfg = _get_config()
        if not cfg.get("idempotency_enabled", True):
            await self.app(scope, receive, send)
            return

        method = (scope.get("method") or "").upper()
        # Default to common mutating methods so tests run without extra config
        allow = {m.upper() for m in (cfg.get("idempotency_methods") or ["POST", "PUT", "PATCH"])}
        if method not in allow:
            await self.app(scope, receive, send)
            return

        req = Request(scope, receive=receive)
        key = req.headers.get("Idempotency-Key")
        if not key:
            await self.app(scope, receive, send)
            return
        if not _KEY_RE.match(key):
            resp: Response = PlainTextResponse("Invalid Idempotency-Key", status_code=400)
            resp.headers["X-Idempotency-Status"] = "invalid"
            resp.headers["Idempotency-Key"] = key
            # For consistency with tests, also surface "not replayed"
            resp.headers["Idempotency-Replayed"] = "false"
            await resp(scope, receive, send)
            return

        tenant, bot = _tenant_bot(req)
        idempotency_seen.labels(tenant=tenant, bot=bot, method=method).inc()

        max_req = int(cfg.get("idempotency_body_max_bytes", 131072) or 0)
        raw = await req.body()
        if max_req and len(raw) > max_req:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="size").inc()

            async def send_wrap(msg: MutableMapping[str, Any]) -> None:
                if msg.get("type") == "http.response.start":
                    headers: List[Tuple[bytes, bytes]] = msg.setdefault("headers", [])
                    headers.append((b"idempotency-key", key.encode("utf-8")))
                    headers.append((b"idempotency-replayed", b"false"))
                    headers.append((b"x-idempotency-status", b"skipped:size"))
                await send(msg)

            await self.app(scope, _reinject_body(raw), send_wrap)
            return

        path = scope.get("path") or ""
        fp = "|".join([method, path, tenant, bot, body_hash(raw)])

        ttl = int(cfg.get("idempotency_ttl_seconds", 86400) or 0)
        retry_after = int(cfg.get("idempotency_in_progress_retry_after", 1) or 1)

        rec = await _STORE.get(key)
        if rec:
            if rec.state == "in_progress":
                idempotency_conflict.labels(
                    tenant=tenant, bot=bot, reason="in_progress"
                ).inc()
                resp = PlainTextResponse("Idempotency in progress", status_code=409)
                resp.headers["Retry-After"] = str(retry_after)
                resp.headers["X-Idempotency-Status"] = "in_progress"
                resp.headers["Idempotency-Key"] = key
                resp.headers["Idempotency-Replayed"] = "false"
                await resp(scope, receive, send)
                return
            if rec.fp != fp:
                idempotency_conflict.labels(
                    tenant=tenant, bot=bot, reason="fingerprint_mismatch"
                ).inc()
                resp = PlainTextResponse("Idempotency conflict", status_code=409)
                resp.headers["X-Idempotency-Status"] = "conflict"
                resp.headers["Idempotency-Key"] = key
                resp.headers["Idempotency-Replayed"] = "false"
                await resp(scope, receive, send)
                return

            # Replayed
            idempotency_replayed.labels(tenant=tenant, bot=bot, method=method).inc()

            # Start from stored headers (preserve custom route headers)
            hdr_list: List[Tuple[str, str]] = list(rec.headers or [])
            # Ensure Content-Type present/consistent
            if rec.ctype:
                # Avoid duplicate differing ctype entries
                if not any(k.lower() == "content-type" for k, _ in hdr_list):
                    hdr_list.append(("Content-Type", rec.ctype))
            # Add idempotency headers for replay
            hdr_list.append(("Idempotency-Key", key))
            hdr_list.append(("Idempotency-Replayed", "true"))

            await Response(rec.body, rec.status, headers=hdr_list)(scope, receive, send)
            return

        # No existing record — mark in progress and capture response
        await _STORE.put_in_progress(key, fp, ttl)

        captured_start: Dict[str, Any] | None = None
        sent_start = False
        buf = bytearray()
        is_stream = False
        status_holder: Dict[str, int] = {"status": 200}
        ctype_holder: Dict[str, str] = {"ctype": ""}
        start_headers_decoded: List[Tuple[str, str]] = []

        def _inject_headers(start_msg: Dict[str, Any], tag: str) -> None:
            hdrs: List[Tuple[bytes, bytes]] = start_msg.setdefault("headers", [])
            hdrs.append((b"idempotency-key", key.encode("utf-8")))
            hdrs.append((b"idempotency-replayed", b"false"))
            hdrs.append((b"x-idempotency-status", tag.encode("utf-8")))

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            nonlocal captured_start, sent_start, is_stream, buf, start_headers_decoded
            t = message.get("type")

            if t == "http.response.start":
                headers_raw = list(message.get("headers") or [])
                captured_start = {
                    "type": t,
                    "status": int(message.get("status", 200)),
                    "headers": headers_raw,
                }
                status_holder["status"] = int(message.get("status", 200))
                # Decode for storage/replay (latin-1 preserves raw octets)
                start_headers_decoded = [
                    (k.decode("latin-1"), v.decode("latin-1")) for k, v in headers_raw
                ]
                try:
                    hdrs_lower = {k.lower(): v for k, v in start_headers_decoded}
                    ctype_holder["ctype"] = hdrs_lower.get("content-type", "")
                except Exception:
                    ctype_holder["ctype"] = ""
                return

            if t == "http.response.body":
                body = message.get("body") or b""
                more = bool(message.get("more_body"))
                if more:
                    is_stream = True
                if not sent_start and captured_start is not None:
                    if is_stream:
                        _inject_headers(captured_start, "skipped:stream")
                    else:
                        tag = "stored" if not (max_req and len(body) > max_req) else "skipped:size"
                        _inject_headers(captured_start, tag)
                    await send(captured_start)
                    sent_start = True
                buf += body
                await send(message)
                return

            await send(message)

        try:
            await self.app(scope, _reinject_body(raw), send_wrapper)
        except Exception:
            await _STORE.clear(key)
            raise

        # Post-processing & persistence
        if is_stream:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="stream").inc()
            await _STORE.clear(key)
            return
        if max_req and len(buf) > max_req:
            idempotency_skipped.labels(tenant=tenant, bot=bot, reason="size").inc()
            await _STORE.clear(key)
            return

        await _STORE.complete(
            key=key,
            status=int(status_holder["status"]),
            body=bytes(buf),
            headers=start_headers_decoded,
            ctype=str(ctype_holder["ctype"] or ""),
            fp=fp,
            ttl=ttl,
        )
