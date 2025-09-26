from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, cast

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import egress_output_report
from app.sanitizers.unicode_sanitizer import sanitize_text
from app.sanitizers.unicode_emoji import analyze_emoji_sequences
from app.sanitizers.markup import looks_like_markup, strip_markup_to_text


class EgressOutputInspectMiddleware(BaseHTTPMiddleware):
    """
    Inspect small JSON/text responses for:
      - zero-width/Bidi/confusable indicators (signals only)
      - emoji TAG/ZWJ hidden ASCII (signals only)
      - HTML/SVG markup presence
    Does NOT change the body content.
    Adds header: X-Guardrail-Egress-Flags: emoji,zwc,markup
    Emits Prometheus counters via egress_output_report().
    Streaming responses are passed through untouched.
    """

    max_bytes = 128 * 1024

    def _is_texty(self, content_type: str) -> bool:
        ct = (content_type or "").lower()
        return (
            "application/json" in ct
            or "text/plain" in ct
            or ct.startswith("text/")
        )

    def _is_streaming(self, resp: Response, ctype: str) -> bool:
        if "text/event-stream" in (ctype or "").lower():
            return True
        r_any = cast(Any, resp)
        has_iter = getattr(r_any, "body_iterator", None) is not None
        no_len = "content-length" not in {k.lower() for k in resp.headers.keys()}
        return bool(has_iter and no_len)

    async def _read_body_bytes(self, resp: Response) -> bytes:
        r_any = cast(Any, resp)
        iterator = getattr(r_any, "body_iterator", None)
        if iterator is None:
            body = getattr(resp, "body", b"")
            return body if isinstance(body, (bytes, bytearray)) else b""

        collected = bytearray()
        async for chunk in iterator:
            if chunk:
                if isinstance(chunk, bytes):
                    data = chunk
                elif isinstance(chunk, str):
                    data = chunk.encode("utf-8")
                else:
                    data = bytes(chunk)
                collected += data
                if len(collected) > self.max_bytes:
                    break
        return bytes(collected)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp = await call_next(request)
        ctype = resp.headers.get("content-type", "")

        # Do not touch streaming; preserve transfer semantics.
        if self._is_streaming(resp, ctype):
            return resp

        body = await self._read_body_bytes(resp)

        if not body or not self._is_texty(ctype) or len(body) > self.max_bytes:
            return Response(
                content=body,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                media_type=resp.media_type,
                background=resp.background,
            )

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return Response(
                content=body,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                media_type=resp.media_type,
                background=resp.background,
            )

        # Unicode controls / bidi / zero-width (stats only)
        _, ustats = sanitize_text(text)
        zero_width = int(ustats.get("zero_width_removed", 0) > 0)
        bidi = int(ustats.get("bidi_controls_removed", 0) > 0)
        conf = int(ustats.get("confusables_mapped", 0) > 0)

        # Emoji TAG/ZWJ derived ASCII (signals only)
        revealed, estats = analyze_emoji_sequences(text)
        emoji_hidden_bytes = len(revealed.encode("utf-8")) if revealed else 0
        emoji_hit = int(emoji_hidden_bytes > 0 or estats.get("zwj", 0) > 0)

        # Markup presence
        markup_hit = 0
        if looks_like_markup(text):
            _, mstats = strip_markup_to_text(text)
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

        # Add compact diagnostic header (non-breaking)
        headers: Dict[str, str] = dict(resp.headers)
        flags: list[str] = []
        if emoji_hit:
            flags.append("emoji")
        if zero_width or bidi or conf:
            flags.append("zwc")
        if markup_hit:
            flags.append("markup")
        if flags:
            prev = headers.get("x-guardrail-egress-flags")
            joined = ",".join(flags) if not prev else f"{prev},{','.join(flags)}"
            headers["X-Guardrail-Egress-Flags"] = joined

        return Response(
            content=body,
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.media_type,
            background=resp.background,
        )
