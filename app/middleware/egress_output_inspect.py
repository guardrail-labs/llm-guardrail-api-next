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


def _accumulate_sample(buf: bytearray, chunk: Any, limit: int) -> None:
    if limit <= len(buf):
        return
    if isinstance(chunk, (bytes, bytearray)):
        take = min(limit - len(buf), len(chunk))
        if take:
            buf += chunk[:take]
    elif isinstance(chunk, str):
        encoded = chunk.encode("utf-8")
        take = min(limit - len(buf), len(encoded))
        if take:
            buf += encoded[:take]


async def _prepare_stream_async(
    iterable: AsyncIterator[Any], limit: int
) -> tuple[AsyncIterator[Any], bytearray]:
    prefix: list[Any] = []
    sample = bytearray()
    exhausted = False

    while len(sample) < limit:
        try:
            chunk = await iterable.__anext__()
        except StopAsyncIteration:
            exhausted = True
            break
        prefix.append(chunk)
        _accumulate_sample(sample, chunk, limit)
        if len(sample) >= limit:
            break

    async def generator() -> AsyncIterator[Any]:
        for chunk in prefix:
            yield chunk
        if not exhausted:
            async for chunk in iterable:
                yield chunk

    return generator(), sample


async def _prepare_stream_sync(
    iterable: Iterator[Any], limit: int
) -> tuple[AsyncIterator[Any], bytearray]:
    prefix: list[Any] = []
    sample = bytearray()
    exhausted = False

    while len(sample) < limit:
        try:
            chunk = next(iterable)
        except StopIteration:
            exhausted = True
            break
        prefix.append(chunk)
        _accumulate_sample(sample, chunk, limit)
        if len(sample) >= limit:
            break

    async def generator() -> AsyncIterator[Any]:
        for chunk in prefix:
            yield chunk
        if not exhausted:
            for chunk in iterable:
                yield chunk

    return generator(), sample


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
            sample = bytearray()
            if hasattr(body_iter, "__anext__"):
                new_iter, sample = await _prepare_stream_async(body_iter, limit)
            else:
                new_iter, sample = await _prepare_stream_sync(
                    cast(Iterator[Any], body_iter), limit
                )
            resp_any.body_iterator = new_iter
            if sample:
                text = sample.decode("utf-8", errors="replace")
                _merge_flags(headers, _scan_flags(text))
            return resp

        body = getattr(resp, "body", b"") or b""
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = cast(bytes, body)

        if len(body_bytes) > limit:
            return resp

        text = body_bytes.decode("utf-8", errors="replace")
        _merge_flags(headers, _scan_flags(text))
        return resp
