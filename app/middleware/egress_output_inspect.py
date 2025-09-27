from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, MutableMapping
from typing import Any, Awaitable, Callable, cast

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app import settings

_ZWC = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u180e"}


def _looks_binary(ct: str | None) -> bool:
    if not ct:
        return False
    ctype = ct.lower()
    if ctype.startswith(("image/", "audio/", "video/")):
        return True
    if ctype in (
        "application/octet-stream",
        "application/zip",
        "application/x-gzip",
    ):
        return True
    return False


def _is_sse(ct: str | None) -> bool:
    return bool(ct and ct.lower().startswith("text/event-stream"))


def _scan_flags(sample: str) -> set[str]:
    out: set[str] = set()
    if any(ch in sample for ch in _ZWC):
        out.add("zwc")
    if "<" in sample and ">" in sample:
        out.add("markup")
    if any("\U0001f000" <= ch <= "\U0010ffff" for ch in sample):
        out.add("emoji")
    return out


def _merge_flags(headers: MutableMapping[str, str], flags: set[str]) -> None:
    if not flags:
        return
    prev = headers.get("X-Guardrail-Egress-Flags", "")
    existing = {token for token in prev.split(",") if token}
    joined = ",".join(sorted(existing | flags))
    headers["X-Guardrail-Egress-Flags"] = joined


def _accum(buf: bytearray, chunk: Any, limit: int, charset: str) -> None:
    if limit <= 0 or len(buf) >= limit:
        return
    if isinstance(chunk, (bytes, bytearray)):
        data = bytes(chunk)
    elif isinstance(chunk, str):
        data = chunk.encode(charset, errors="replace")
    else:
        try:
            data = bytes(chunk)
        except Exception:
            data = str(chunk).encode(charset, errors="replace")
    take = min(limit - len(buf), len(data))
    if take:
        buf += data[:take]


async def _wrap_async_stream(
    iterable: AsyncIterator[Any],
    resp: Response,
    limit: int,
    content_type: str | None,
) -> AsyncIterator[Any]:
    prefix: list[Any] = []
    sample = bytearray()
    exhausted = False
    charset = getattr(resp, "charset", None) or "utf-8"

    while len(sample) < limit:
        try:
            chunk = await iterable.__anext__()
        except StopAsyncIteration:
            exhausted = True
            break
        prefix.append(chunk)
        _accum(sample, chunk, limit, charset)

    _apply_sample_flags(resp, sample, limit, content_type, charset)

    async def generator() -> AsyncIterator[Any]:
        nonlocal exhausted
        try:
            for chunk in prefix:
                yield chunk
            if not exhausted:
                try:
                    async for chunk in iterable:
                        _accum(sample, chunk, limit, charset)
                        yield chunk
                except Exception:
                    raise
                else:
                    exhausted = True
        finally:
            _apply_sample_flags(resp, sample, limit, content_type, charset)
            if not exhausted:
                aclose = getattr(iterable, "aclose", None)
                if aclose is not None:
                    try:
                        await aclose()
                    except Exception:
                        pass

    return generator()


async def _wrap_sync_stream(
    iterable: Iterator[Any],
    resp: Response,
    limit: int,
    content_type: str | None,
) -> AsyncIterator[Any]:
    prefix: list[Any] = []
    sample = bytearray()
    exhausted = False
    charset = getattr(resp, "charset", None) or "utf-8"

    while len(sample) < limit:
        try:
            chunk = next(iterable)
        except StopIteration:
            exhausted = True
            break
        prefix.append(chunk)
        _accum(sample, chunk, limit, charset)

    _apply_sample_flags(resp, sample, limit, content_type, charset)

    async def generator() -> AsyncIterator[Any]:
        nonlocal exhausted
        try:
            for chunk in prefix:
                yield chunk
            if not exhausted:
                try:
                    for chunk in iterable:
                        _accum(sample, chunk, limit, charset)
                        yield chunk
                except Exception:
                    raise
                else:
                    exhausted = True
        finally:
            _apply_sample_flags(resp, sample, limit, content_type, charset)
            if not exhausted:
                close = getattr(iterable, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception:
                        pass

    return generator()


def _apply_sample_flags(
    resp: Response,
    sample: bytearray,
    limit: int,
    content_type: str | None,
    charset: str,
) -> None:
    if limit <= 0 or not sample or _looks_binary(content_type):
        return
    text = sample.decode(charset, errors="replace")
    headers = cast(MutableMapping[str, str], resp.headers)
    _merge_flags(headers, _scan_flags(text))


class EgressOutputInspectMiddleware(BaseHTTPMiddleware):
    """Inspect small text responses for emoji/markup/zero-width flags."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp = await call_next(request)
        headers = cast(MutableMapping[str, str], resp.headers)
        content_type = resp.headers.get("Content-Type") or resp.media_type
        resp_any = cast(Any, resp)
        body_iter = getattr(resp_any, "body_iterator", None)
        is_stream = body_iter is not None

        if is_stream or _is_sse(content_type):
            if "Content-Length" in resp.headers:
                del resp.headers["Content-Length"]

        limit = settings.EGRESS_INSPECT_MAX_BYTES
        if limit <= 0 or _looks_binary(content_type):
            return resp

        if is_stream and body_iter is not None:
            if hasattr(body_iter, "__anext__"):
                resp_any.body_iterator = await _wrap_async_stream(
                    cast(AsyncIterator[Any], body_iter),
                    resp,
                    limit,
                    content_type,
                )
            else:
                resp_any.body_iterator = await _wrap_sync_stream(
                    cast(Iterator[Any], body_iter),
                    resp,
                    limit,
                    content_type,
                )
            return resp

        body = getattr(resp, "body", b"") or b""
        charset = getattr(resp, "charset", None) or "utf-8"
        if isinstance(body, str):
            body_bytes = body.encode(charset, errors="replace")
        else:
            body_bytes = cast(bytes, body)

        if len(body_bytes) > limit:
            return resp

        text = body_bytes.decode(charset, errors="replace")
        _merge_flags(headers, _scan_flags(text))
        return resp
