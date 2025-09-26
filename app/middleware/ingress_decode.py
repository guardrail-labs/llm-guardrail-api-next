from __future__ import annotations

import json
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.sanitizers.encoding_sanitizer import decode_string_once
from app.observability.metrics import decode_ingress_report

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"


def _walk(obj):
    """
    Generator over all string fields in a JSON-like object,
    yielding (container, key_or_index, value_str).
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield obj, k, v
            else:
                yield from _walk(v)
        # Keys can be strings; we leave keys unchanged to avoid breaking schemas.
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield obj, i, v
            else:
                yield from _walk(v)


class DecodeIngressMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attempts a single safe layer of decoding
    (base64, hex, URL) on string values in JSON bodies.
    Emits Prometheus counters for observability.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        ctype = request.headers.get("content-type", "").lower()
        if "application/json" not in ctype:
            return await call_next(request)

        raw = await request.body()
        if not raw:
            return await call_next(request)

        try:
            data = json.loads(raw)
        except Exception:
            return await call_next(request)

        # Attempt a single decode pass across strings
        dec_b64 = 0
        dec_hex = 0
        dec_url = 0
        changed = False

        for container, key, val in _walk(data):
            new_val, stats = decode_string_once(val)
            if stats.get("changed"):
                container[key] = new_val
                changed = True
            dec_b64 += stats.get("decoded_base64", 0)
            dec_hex += stats.get("decoded_hex", 0)
            dec_url += stats.get("decoded_url", 0)

        decode_ingress_report(
            tenant=tenant,
            bot=bot,
            decoded_base64=dec_b64,
            decoded_hex=dec_hex,
            decoded_url=dec_url,
        )

        if not changed:
            return await call_next(request)

        new_body = json.dumps(data).encode("utf-8")

        async def receive() -> dict:
            return {"type": "http.request", "body": new_body, "more_body": False}

        new_request = Request(request.scope, receive)
        return await call_next(new_request)
