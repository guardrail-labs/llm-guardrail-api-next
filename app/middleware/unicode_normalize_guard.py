"""Ingress middleware for Unicode normalization and confusables detection."""
# Tenant-aware Unicode normalization + confusables guard middleware.

from __future__ import annotations

from typing import Optional

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.services.unicode_confusables import ConfusablesReport, sanitize_text


class UnicodeNormalizeGuard:
    """
    Ingress sanitizer for Unicode normalization + confusables check.

    Modes (by tenant, default process-wide fallback):
      - normalize      : NFC/NFKC normalization (default NFC)
      - strip          : replace known confusables with ASCII lookalikes, then normalize
      - block          : raise 400 if mixed scripts or confusables detected
      - report-only    : no mutation, attach observability headers only
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_mode: str = "normalize",
        norm_form: str = "NFC",
        max_body_bytes: int = 1_000_000,
    ) -> None:
        self.app = app
        self.default_mode = default_mode
        self.norm_form = norm_form
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        header_map = {k.lower(): v for k, v in raw_headers}
        tenant = header_map.get(b"x-tenant-id", b"").decode("utf-8", "ignore")
        mode = header_map.get(b"x-confusables-mode", b"").decode("utf-8", "ignore")
        form = header_map.get(b"x-confusables-form", b"").decode("utf-8", "ignore")
        mode = mode or self.default_mode
        form = form or self.norm_form

        body = bytearray()
        disconnect_msg: Optional[Message] = None
        more_body = True

        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                if chunk:
                    body.extend(chunk)
                if len(body) > self.max_body_bytes:
                    await _send_413(scope, send)
                    return
                more_body = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                disconnect_msg = message
                break
            else:
                more_body = False

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            await self._forward(scope, bytes(body), send, None, disconnect_msg)
            return

        new_text, report = sanitize_text(text, mode=mode, form=form)

        if report and tenant:
            _store_report(scope, tenant, report)

        if mode.lower() == "block" and report and (
            report.has_mixed_scripts or report.confusable_pairs
        ):
            await _send_400(scope, send, report)
            return

        new_body = new_text.encode("utf-8")
        await self._forward(scope, new_body, send, report, disconnect_msg)

    async def _forward(
        self,
        scope: Scope,
        body: bytes,
        send: Send,
        report: Optional[ConfusablesReport],
        disconnect_msg: Optional[Message],
    ) -> None:
        headers = list(scope.get("headers", []))
        body_len = str(len(body)).encode("latin-1")
        replaced = False
        for idx, (key, value) in enumerate(headers):
            if key.lower() == b"content-length":
                headers[idx] = (key, body_len)
                replaced = True
        if not replaced:
            headers.append((b"content-length", body_len))
        scope = dict(scope)
        scope["headers"] = headers

        body_sent = False
        disconnect_pending = disconnect_msg is not None

        async def receive_wrapper() -> Message:
            nonlocal body_sent, disconnect_pending
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            if disconnect_pending and disconnect_msg is not None:
                disconnect_pending = False
                return disconnect_msg
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and report is not None:
                hdrs = list(message.get("headers", []))
                hdrs.append(
                    (b"x-confusables-non-ascii",
                     b"1" if report.has_non_ascii else b"0")
                )
                hdrs.append(
                    (b"x-confusables-mixed",
                     b"1" if report.has_mixed_scripts else b"0")
                )
                hdrs.append(
                    (
                        b"x-confusables-pairs",
                        str(len(report.confusable_pairs)).encode("utf-8"),
                    )
                )
                hdrs.append(
                    (
                        b"x-confusables-norm-changed",
                        b"1" if report.normalized_changed else b"0",
                    )
                )
                message = dict(message)
                message["headers"] = hdrs
            await send(message)

        await self.app(scope, receive_wrapper, send_wrapper)


def _store_report(scope: Scope, tenant: str, report: ConfusablesReport) -> None:
    state = scope.setdefault("state", {})
    if isinstance(state, dict):
        state.setdefault("confusables", {})[tenant] = report
    else:
        setattr(state, "unicode_confusables_report", report)


async def _send_413(scope: Scope, send: Send) -> None:
    resp = JSONResponse({"error": "request entity too large"}, status_code=413)

    async def _empty_receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    await resp(scope, _empty_receive, send)


async def _send_400(scope: Scope, send: Send, rep: ConfusablesReport) -> None:
    payload = {
        "error": "blocked due to unicode confusables/mixed scripts",
        "mixed_scripts": rep.has_mixed_scripts,
        "pairs": rep.confusable_pairs,
        "norm_form": rep.norm_form,
    }
    resp = JSONResponse(payload, status_code=400)

    async def _empty_receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    await resp(scope, _empty_receive, send)
