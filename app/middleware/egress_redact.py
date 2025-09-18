from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.types import ASGIApp

from app.observability.metrics import inc_egress_redactions
from app.services.egress import redact_text
from app.shared.headers import BOT_HEADER, TENANT_HEADER

STREAM_LIKE_CT = ("text/event-stream",)


def _redact_enabled(request: Request) -> bool:
    try:
        app_state = getattr(request.app, "state", None)
        settings = getattr(app_state, "settings", None)
        if settings is not None:
            egress_settings = getattr(settings, "egress", settings)
            val = getattr(egress_settings, "redact_enabled", None)
            if val is None:
                val = getattr(settings, "egress_redact_enabled", None)
            if val is not None:
                return bool(val)
    except Exception:
        pass
    return os.getenv("EGRESS_REDACT_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def _merge_counts(target: Dict[str, int], counts: Dict[str, int]) -> None:
    for key, value in counts.items():
        if value:
            target[key] = target.get(key, 0) + int(value)


def _emit_metrics(counts: Dict[str, int], tenant: str, bot: str, kind: str) -> None:
    for rule_id, count in counts.items():
        if count:
            inc_egress_redactions(tenant, bot, kind, n=int(count), rule_id=rule_id)


def _emit_decision_hooks(request: Request, counts: Dict[str, int]) -> None:
    total_replacements = sum(int(value or 0) for value in counts.values())
    if not total_replacements:
        return

    tenant_state = getattr(request.state, "tenant", None)
    bot_state = getattr(request.state, "bot", None)

    try:
        from app.observability import metrics_decisions as _md

        for rule_id, count in counts.items():
            if not count:
                continue
            for _ in range(int(count or 1)):
                _md.inc_redact(
                    rule_id,
                    tenant=tenant_state,
                    bot=bot_state,
                )
        _md.inc("redact", tenant=tenant_state, bot=bot_state)
    except Exception:
        pass

    tenant_value = (
        tenant_state
        if tenant_state is not None
        else request.headers.get(TENANT_HEADER, "unknown")
    )
    bot_value = (
        bot_state
        if bot_state is not None
        else request.headers.get(BOT_HEADER, "unknown")
    )

    try:
        from app.services import decisions as decisions_store

        redactions = [
            {"rule_id": rid, "count": int(ct)}
            for rid, ct in counts.items()
            if ct
        ]
        if not redactions:
            return
        decisions_store.record(
            id=f"redact-{int(time.time() * 1000)}",
            tenant=str(tenant_value or "unknown"),
            bot=str(bot_value or "unknown"),
            outcome="redact",
            details={"redactions": redactions},
        )
    except Exception:
        pass


def _redact_obj(value: Any, counts: Dict[str, int]) -> Any:
    if isinstance(value, str):
        redacted, rule_counts = redact_text(value)
        _merge_counts(counts, rule_counts)
        return redacted
    if isinstance(value, list):
        return [_redact_obj(item, counts) for item in value]
    if isinstance(value, dict):
        return {key: _redact_obj(item, counts) for key, item in value.items()}
    return value


async def _restore_body(response: Response, body: bytes) -> None:
    async def _aiter():
        yield body

    response.headers["content-length"] = str(len(body))
    setattr(response, "body_iterator", _aiter())


class EgressRedactMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        if not _redact_enabled(request):
            return response

        raw_content_type = response.headers.get("content-type") or ""
        content_type = raw_content_type.lower()
        if not any(token in content_type for token in ("text", "json", "html")):
            return response

        transfer_encoding = (response.headers.get("transfer-encoding") or "").lower()

        # Preserve streaming semantics by skipping known streaming types/content
        if (
            isinstance(response, StreamingResponse)
            or any(token in content_type for token in STREAM_LIKE_CT)
            or "chunked" in transfer_encoding
        ):
            return response

        content_length_raw = response.headers.get("content-length")
        if content_length_raw is None:
            return response
        try:
            int(content_length_raw)
        except (TypeError, ValueError):
            return response

        kind_label = content_type.split(";", 1)[0] or "text/plain"

        body_chunks: list[bytes] = []
        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is not None:
            async for chunk in body_iterator:
                body_chunks.append(bytes(chunk))
        body = b"".join(body_chunks)
        try:
            charset = response.charset or "utf-8"
            text = body.decode(charset, errors="replace")
        except Exception:
            text = body.decode("utf-8", errors="replace")

        tenant = request.headers.get(TENANT_HEADER, "default")
        bot = request.headers.get(BOT_HEADER, "default")

        headers = dict(response.headers)
        headers.pop("content-length", None)

        if "json" in content_type:
            counts: Dict[str, int] = {}
            try:
                parsed = json.loads(text)
            except Exception:
                new_text, rule_counts = redact_text(text)
                if not rule_counts:
                    await _restore_body(response, body)
                    return response
                _emit_metrics(rule_counts, tenant, bot, kind_label)
                _emit_decision_hooks(request, rule_counts)
                return PlainTextResponse(
                    new_text,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=response.media_type,
                    background=response.background,
                )

            redacted = _redact_obj(parsed, counts)
            if not counts:
                await _restore_body(response, body)
                return response

            payload = json.dumps(redacted, ensure_ascii=False)
            _emit_metrics(counts, tenant, bot, "application/json")
            _emit_decision_hooks(request, counts)
            return Response(
                content=payload,
                status_code=response.status_code,
                headers=headers,
                media_type="application/json",
                background=response.background,
            )

        new_text, rule_counts = redact_text(text)
        if not rule_counts:
            await _restore_body(response, body)
            return response

        _emit_metrics(rule_counts, tenant, bot, kind_label)
        _emit_decision_hooks(request, rule_counts)
        return PlainTextResponse(
            new_text,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
            background=response.background,
        )
