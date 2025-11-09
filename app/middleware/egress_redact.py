from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator
from typing import Any, Callable, Dict, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp

from app.observability.metrics import inc_egress_redactions
from app.services.egress import redact_text
from app.shared.headers import BOT_HEADER, TENANT_HEADER


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
        tenant_state if tenant_state is not None else request.headers.get(TENANT_HEADER, "unknown")
    )
    bot_value = bot_state if bot_state is not None else request.headers.get(BOT_HEADER, "unknown")

    try:
        from app.services import decisions as decisions_store

        redactions = [{"rule_id": rid, "count": int(ct)} for rid, ct in counts.items() if ct]
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


def _choose_encoding(headers: Dict[str, str]) -> str:
    content_type = (headers.get("content-type") or "").lower()
    if "charset=" in content_type:
        try:
            return content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        except Exception:
            return "utf-8"
    return "utf-8"


async def _windowed_redact_gen(
    chunks_async_iter: AsyncIterator[Any],
    apply_redactions: Callable[[str], tuple[str, Dict[str, int]]],
    encoding: str,
    window_bytes: int,
) -> AsyncIterator[bytes]:
    from app.observability import metrics_redaction as _metrics_redaction

    enc = encoding or "utf-8"
    carry_limit = max(int(window_bytes or 0), 1)
    scan_tail = ""
    pending = ""
    first_chunk = True

    async for chunk in chunks_async_iter:
        if isinstance(chunk, bytes):
            chunk_bytes = chunk
        elif isinstance(chunk, str):
            chunk_bytes = chunk.encode(enc, errors="ignore")
        else:
            chunk_bytes = bytes(chunk)

        _metrics_redaction.add_scanned(len(chunk_bytes))

        decoded = chunk_bytes.decode(enc, errors="replace")
        work_text = scan_tail + decoded
        redacted, _rule_counts = apply_redactions(work_text)

        if not first_chunk:
            _metrics_redaction.inc_overlap()
        first_chunk = False

        if len(redacted) > carry_limit:
            emit = redacted[:-carry_limit]
            pending = redacted[-carry_limit:]
        else:
            emit = ""
            pending = redacted

        if emit:
            yield emit.encode(enc)

        scan_tail = work_text[-carry_limit:] if len(work_text) > carry_limit else work_text

    if pending:
        yield pending.encode(enc)


class EgressRedactMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if not _redact_enabled(request):
            return response

        raw_content_type = response.headers.get("content-type") or ""
        content_type = raw_content_type.lower()
        if not any(token in content_type for token in ("text", "json", "html")):
            return response

        is_sse = "text/event-stream" in content_type
        if is_sse:
            response.headers.setdefault("X-Redaction-Skipped", "streaming")
            try:
                from app.observability import metrics_redaction as _metrics_redaction

                _metrics_redaction.inc_skipped("streaming")
            except Exception:
                pass
            return response

        body_iterator = getattr(response, "body_iterator", None)
        content_length_raw = response.headers.get("content-length")

        if (
            body_iterator is not None
            and content_length_raw is None
            and any(token in content_type for token in ("text", "json", "html"))
        ):
            chunks_iter = cast(AsyncIterator[Any], body_iterator)
            tenant = request.headers.get(TENANT_HEADER, "default")
            bot = request.headers.get(BOT_HEADER, "default")
            kind_label = content_type.split(";", 1)[0] or "text/plain"

            window_bytes_raw = os.getenv("EGRESS_REDACT_WINDOW_BYTES", "256")
            try:
                window_bytes = int(window_bytes_raw)
            except (TypeError, ValueError):
                window_bytes = 256
            window_bytes = max(window_bytes, 1)

            stream_counts: Dict[str, int] = {}
            encoding = _choose_encoding(dict(response.headers))

            def _apply(text: str) -> tuple[str, Dict[str, int]]:
                redacted_text, rule_counts = redact_text(text)
                _merge_counts(stream_counts, rule_counts)
                return redacted_text, rule_counts

            async def _redacted_stream() -> AsyncIterator[bytes]:
                try:
                    async for out in _windowed_redact_gen(
                        chunks_iter, _apply, encoding, window_bytes
                    ):
                        yield out
                finally:
                    close_fn = getattr(chunks_iter, "aclose", None)
                    if callable(close_fn):
                        try:
                            await close_fn()
                        except Exception:
                            pass
                    else:
                        sync_close = getattr(chunks_iter, "close", None)
                        if callable(sync_close):
                            try:
                                sync_close()
                            except Exception:
                                pass
                    if stream_counts:
                        _emit_metrics(stream_counts, tenant, bot, kind_label)
                        _emit_decision_hooks(request, stream_counts)

            from starlette.responses import StreamingResponse as _StreamingResponse

            new_response = _StreamingResponse(
                _redacted_stream(),
                status_code=response.status_code,
                media_type=response.media_type,
                background=response.background,
            )

            try:
                raw_headers = getattr(response, "raw_headers", None)
                if raw_headers:
                    for key_bytes, value_bytes in raw_headers:
                        key = key_bytes.decode("latin-1")
                        if key.lower() == "content-length":
                            continue
                        new_response.headers.append(key, value_bytes.decode("latin-1"))
                else:
                    for key, value in response.headers.items():
                        if key.lower() == "content-length":
                            continue
                        new_response.headers.append(key, value)
            except Exception:
                for key, value in response.headers.items():
                    if key.lower() == "content-length":
                        continue
                    new_response.headers[key] = value

            new_response.headers["X-Redaction-Mode"] = "windowed"
            return new_response

        if content_length_raw is None:
            return response
        try:
            int(content_length_raw)
        except (TypeError, ValueError):
            return response

        kind_label = content_type.split(";", 1)[0] or "text/plain"

        max_bytes = int(os.getenv("EGRESS_REDACT_MAX_BYTES", str(1024 * 1024)))
        body_chunks: list[bytes] = []
        body_iterator = getattr(response, "body_iterator", None)
        if body_iterator is not None:
            total = 0
            async for chunk in body_iterator:
                b = bytes(chunk)
                body_chunks.append(b)
                total += len(b)
                if total > max_bytes:
                    response.headers.setdefault("X-Redaction-Skipped", "oversize")
                    try:
                        from app.observability import metrics_redaction as _metrics_redaction

                        _metrics_redaction.inc_skipped("oversize")
                    except Exception:
                        pass

                    async def _gen(
                        prefix: list[bytes], rest: AsyncIterator[bytes]
                    ) -> AsyncIterator[bytes]:
                        for p in prefix:
                            yield p
                        async for ch in rest:
                            yield ch

                    from starlette.responses import StreamingResponse as _StreamingResponse

                    passthrough = _gen(body_chunks[:], body_iterator)
                    new_resp = _StreamingResponse(
                        passthrough,
                        status_code=response.status_code,
                        background=response.background,
                    )
                    try:
                        raw_headers = getattr(response, "raw_headers", None)
                        if raw_headers:
                            for key_bytes, value_bytes in raw_headers:
                                key = key_bytes.decode("latin-1")
                                if key.lower() == "content-length":
                                    continue
                                new_resp.headers.append(key, value_bytes.decode("latin-1"))
                        else:
                            for key, value in response.headers.items():
                                if key.lower() == "content-length":
                                    continue
                                new_resp.headers.append(key, value)
                    except Exception:
                        for key, value in response.headers.items():
                            if key.lower() == "content-length":
                                continue
                            new_resp.headers[key] = value
                    new_resp.headers["X-Redaction-Skipped"] = "oversize"
                    return new_resp
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
            json_counts: Dict[str, int] = {}
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

            redacted = _redact_obj(parsed, json_counts)
            if not json_counts:
                await _restore_body(response, body)
                return response

            payload = json.dumps(redacted, ensure_ascii=False)
            _emit_metrics(json_counts, tenant, bot, "application/json")
            _emit_decision_hooks(request, json_counts)
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
