from __future__ import annotations

import unicodedata as ud
from typing import Literal, Optional, cast

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_NormalForm = Literal["NFC", "NFD", "NFKC", "NFKD"]


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

        body, disconnect = await self._collect_body(receive)
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

    async def _collect_body(self, receive: Receive) -> tuple[bytes, Optional[Message]]:
        body_parts: list[bytes] = []
        disconnect: Optional[Message] = None
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                disconnect = message
                break
            chunk = message.get("body", b"")
            if chunk:
                body_parts.append(chunk)
            more = bool(message.get("more_body", False))
        return b"".join(body_parts), disconnect

    def _normalize(self, body: bytes) -> tuple[bytes, bool]:
        if not body:
            return body, False
        if self._max_bytes and len(body) > self._max_bytes:
            return body, False
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body, False
        normalized = ud.normalize(self._form, text)
        if normalized == text:
            return body, False
        return normalized.encode("utf-8"), True
