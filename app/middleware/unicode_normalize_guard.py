from __future__ import annotations

import unicodedata as ud
from collections import Counter
from typing import Literal, Optional, cast

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import settings
from app.observability.metrics import inc_sanitizer_confusable_detected
from app.sanitizers.unicode_sanitizer import detect_unicode_anomalies

_NormalForm = Literal["NFC", "NFD", "NFKC", "NFKD"]
_CollectError = Literal["too_large", "other"]


class UnicodeNormalizeGuard:
    """Normalize inbound request bodies before downstream processing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_mode: str = "pass",
        norm_form: str = "NFKC",
        max_body_bytes: int = 131072,
    ) -> None:
        self.app = app
        self._mode = default_mode
        form_upper = norm_form.upper()
        if form_upper not in {"NFC", "NFD", "NFKC", "NFKD"}:
            form_upper = "NFKC"
        self._form = cast(_NormalForm, form_upper)
        self._max_bytes = max(0, int(max_body_bytes))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        body, err, disconnect = await self._collect_body(receive)
        unicode_summary = None
        if body and settings.SANITIZER_CONFUSABLES_ENABLED:
            try:
                text_for_detection = body.decode("utf-8")
            except UnicodeDecodeError:
                text_for_detection = None
            else:
                anomalies = detect_unicode_anomalies(text_for_detection)
                if anomalies:
                    totals: Counter[str] = Counter()
                    samples: dict[str, dict[str, str]] = {}
                    for finding in anomalies:
                        kind = finding["type"]
                        totals[kind] += 1
                        inc_sanitizer_confusable_detected(kind)
                        samples.setdefault(
                            kind,
                            {"char": finding["char"], "codepoint": finding["codepoint"]},
                        )
                    unicode_summary = {
                        "totals_by_type": {k: int(v) for k, v in totals.items()},
                        "sample_chars": samples,
                    }
                    scope.setdefault("state", {})["unicode_findings_summary"] = unicode_summary
                    scope["unicode_findings_summary"] = unicode_summary
        if err == "too_large":
            await _send_413(send)
            return
        normalized_body, changed = self._normalize(body)
        if changed:
            scope.setdefault("state", {})["unicode_normalized"] = True

        body_sent = False

        async def receive_wrapper() -> Message:
            nonlocal body_sent, disconnect
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": normalized_body, "more_body": False}
            if disconnect is not None:
                message = disconnect
                disconnect = None
                return message
            return await receive()

        async def send_wrapper(message: Message) -> None:
            if changed and message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append(
                    (
                        b"x-guardrail-unicode",
                        f"normalized;mode={self._mode};form={self._form}".encode("ascii"),
                    )
                )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive_wrapper, send_wrapper)

    async def _collect_body(
        self, receive: Receive
    ) -> tuple[bytes, Optional[_CollectError], Optional[Message]]:
        """Drain request body while enforcing max size incrementally."""
        parts: list[bytes] = []
        total = 0
        disconnect: Optional[Message] = None
        while True:
            message = await receive()
            if message["type"] != "http.request":
                disconnect = message
                return b"".join(parts), "other", disconnect
            chunk = message.get("body", b"")
            if chunk:
                total += len(chunk)
                if self._max_bytes and total > self._max_bytes:
                    return b"", "too_large", None
                parts.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(parts), None, None

    def _normalize(self, body: bytes) -> tuple[bytes, bool]:
        if not body:
            return body, False
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body, False
        normalized = ud.normalize(self._form, text)
        if normalized == text:
            return body, False
        return normalized.encode("utf-8"), True


async def _send_413(send: Send) -> None:
    body = b'{"code":"payload_too_large"}'
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"connection", b"close"),
    ]
    await send({"type": "http.response.start", "status": 413, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})
