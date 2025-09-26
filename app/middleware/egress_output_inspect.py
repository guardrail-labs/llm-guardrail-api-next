from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable, cast

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

from app.observability.metrics import egress_output_report
from app.sanitizers.unicode_sanitizer import sanitize_text
from app.sanitizers.unicode_emoji import analyze_emoji_sequences
from app.sanitizers.markup import looks_like_markup, strip_markup_to_text


class EgressOutputInspectMiddleware(BaseHTTPMiddleware):
    """
    Inspect small JSON/text responses for:
      - zero-width/Bidi/confusable mapping (via sanitize_text stats)
      - emoji TAG/ZWJ derived ASCII (no mutation)
      - HTML/SVG markup presence
    Does NOT change the body. Adds a diagnostic header:
      X-Guardrail-Egress-Flags: emoji,zwc,markup
    and emits Prometheus counters via egress_output_report().
    """

    # Only inspect bodies up to this size (bytes)
    max_bytes = 128 * 1024

    def _is_texty(self, content_type: str) -> bool:
        ct = (content_type or "").lower()
        return (
            "application/json" in ct
            or "text/plain" in ct
            or ct.startswith("text/")
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp = await call_next(request)

        ctype = resp.headers.get("content-type", "")
        transfer_enc = (resp.headers.get("transfer-encoding") or "").lower()
        if (
            not self._is_texty(ctype)
            or isinstance(resp, StreamingResponse)
            or "chunked" in transfer_enc
            or "text/event-stream" in ctype
        ):
            return resp

        body_bytes: bytes | None = None
        had_content_length = "content-length" in {
            key.lower() for key in resp.headers.keys()
        }
        body_iterator = cast(
            AsyncIterator[Any] | None, getattr(resp, "body_iterator", None)
        )
        if body_iterator is not None:
            chunks: list[bytes] = []

            async for chunk in body_iterator:
                if isinstance(chunk, bytes):
                    chunk_bytes = chunk
                elif isinstance(chunk, str):
                    chunk_bytes = chunk.encode("utf-8")
                else:
                    chunk_bytes = bytes(chunk)
                chunks.append(chunk_bytes)
            if not chunks:
                chunks = [b""]

            body_bytes = b"".join(chunks)

            async def _aiter() -> AsyncIterator[bytes]:
                for chunk in chunks:
                    yield chunk

            resp.body_iterator = _aiter()
            if had_content_length:
                resp.headers["content-length"] = str(len(body_bytes))
            setattr(resp, "body", body_bytes)
        else:
            body_raw = getattr(resp, "body", b"")
            if isinstance(body_raw, (bytes, bytearray)):
                body_bytes = bytes(body_raw)
            elif isinstance(body_raw, str):
                body_bytes = body_raw.encode("utf-8")
            else:
                try:
                    body_bytes = bytes(body_raw)
                except Exception:
                    body_bytes = None

        if not body_bytes or len(body_bytes) > self.max_bytes:
            return resp

        try:
            text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            return resp

        # 1) Unicode controls / bidi / zero-width (stats only)
        _, ustats = sanitize_text(text)
        zero_width = int(ustats.get("zero_width_removed", 0) > 0)
        bidi = int(ustats.get("bidi_controls_removed", 0) > 0)
        conf = int(ustats.get("confusables_mapped", 0) > 0)

        # 2) Emoji TAG/ZWJ derived ASCII (do not inject)
        revealed, estats = analyze_emoji_sequences(text)
        emoji_hidden_bytes = len(revealed.encode("utf-8")) if revealed else 0
        emoji_hit = int(emoji_hidden_bytes > 0 or estats.get("zwj", 0) > 0)

        # 3) Markup presence
        has_markup = looks_like_markup(text)
        markup_hit = 0
        if has_markup:
            _, mstats = strip_markup_to_text(text)
            # If any tag/script/style removed, we treat as a hit
            if any(
                mstats.get(k, 0) > 0
                for k in (
                    "scripts_removed",
                    "styles_removed",
                    "foreign_removed",
                    "tags_removed",
                )
            ):
                markup_hit = 1

        # Emit metrics
        egress_output_report(
            zero_width=zero_width,
            bidi=bidi,
            confusable=conf,
            emoji_hidden_bytes=emoji_hidden_bytes,
            emoji_zwj=estats.get("zwj", 0),
            markup=markup_hit,
        )

        # Add a compact diagnostic header (non-breaking)
        flags: list[str] = []
        if emoji_hit:
            flags.append("emoji")
        if zero_width or bidi or conf:
            flags.append("zwc")
        if markup_hit:
            flags.append("markup")
        if flags:
            # Preserve any existing value by appending
            prev = resp.headers.get("x-guardrail-egress-flags")
            joined = ",".join(flags) if not prev else f"{prev},{','.join(flags)}"
            resp.headers["X-Guardrail-Egress-Flags"] = joined

        return resp
