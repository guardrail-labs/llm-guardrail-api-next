from __future__ import annotations

import json
from typing import Any, Dict

from starlette.datastructures import UploadFile
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.ingress.multimodal import (
    detect_injection,
    estimate_base64_size,
    extract_from_base64_image,
    extract_from_image,
    extract_from_pdf,
    image_supported,
    pdf_supported,
    sniff_mime,
)
from app.metrics_sanitizer import sanitizer_actions, sanitizer_events
from app.policy.multimodal import (
    get_multimodal_flags,
    get_tenant_id_from_headers,
)

JsonObj = Dict[str, Any]
_BASE64_KEYS = ("image", "img", "file_b64", "attachment_b64")


def _make_receive(raw: bytes):
    sent = False

    async def _receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return _receive


async def _read_upload(upload: UploadFile, max_bytes: int) -> tuple[bytes, bool]:
    raw = await upload.read()
    if len(raw) > max_bytes:
        return b"", True
    return raw, False


def _scan_text(tenant: str, text: str) -> int:
    if not text:
        return 0
    hits = detect_injection(text)
    if hits:
        sanitizer_events.labels(tenant, "multimodal_injection").inc(hits)
    return hits


def _json_body(raw: bytes) -> JsonObj | None:
    if not raw:
        return None
    try:
        decoded = raw.decode("utf-8")
        data = json.loads(decoded)
    except Exception:
        return None
    if isinstance(data, dict):
        return data
    return None


class MultimodalGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        tenant = get_tenant_id_from_headers(request.headers.get)
        flags = get_multimodal_flags(tenant)

        if not flags.enabled:
            return await call_next(request)

        method = request.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        ctype = request.headers.get("content-type", "").lower()
        hits = 0
        inspected = False

        response: Response | None = None
        try:
            if "multipart/form-data" in ctype:
                inspected = True
                raw_body = await request.body()
                form = await request.form()
                for _, val in form.multi_items():
                    if not isinstance(val, UploadFile):
                        continue
                    family = sniff_mime(val.filename, val.content_type)
                    if family == "pdf":
                        if not pdf_supported():
                            sanitizer_events.labels(
                                tenant, "multimodal_pdf_unsupported"
                            ).inc()
                            continue
                        raw, too_large = await _read_upload(val, flags.max_bytes)
                        if too_large:
                            sanitizer_events.labels(
                                tenant, "multimodal_too_large"
                            ).inc()
                            continue
                        if not raw:
                            continue
                        sanitizer_events.labels(tenant, "multimodal_scan").inc()
                        text = extract_from_pdf(raw)
                        hits += _scan_text(tenant, text)
                    elif family == "image":
                        if not image_supported():
                            sanitizer_events.labels(
                                tenant, "multimodal_image_unsupported"
                            ).inc()
                            continue
                        raw, too_large = await _read_upload(val, flags.max_bytes)
                        if too_large:
                            sanitizer_events.labels(
                                tenant, "multimodal_too_large"
                            ).inc()
                            continue
                        if not raw:
                            continue
                        sanitizer_events.labels(tenant, "multimodal_scan").inc()
                        text = extract_from_image(raw)
                        hits += _scan_text(tenant, text)
                new_request = Request(request.scope, _make_receive(raw_body))
                response = await call_next(new_request)
            elif "application/json" in ctype:
                inspected = True
                raw_body = await request.body()
                data = _json_body(raw_body)
                if data is not None:
                    for key in _BASE64_KEYS:
                        value = data.get(key)
                        if not isinstance(value, str):
                            continue
                        if not image_supported():
                            sanitizer_events.labels(
                                tenant, "multimodal_image_unsupported"
                            ).inc()
                            continue
                        estimated = estimate_base64_size(value)
                        if estimated > flags.max_bytes:
                            sanitizer_events.labels(
                                tenant, "multimodal_too_large"
                            ).inc()
                            continue
                        sanitizer_events.labels(tenant, "multimodal_scan").inc()
                        text = extract_from_base64_image(value)
                        hits += _scan_text(tenant, text)
                new_request = Request(request.scope, _make_receive(raw_body))
                response = await call_next(new_request)
            else:
                response = await call_next(request)
        except Exception:
            sanitizer_events.labels(tenant, "multimodal_error").inc()
            response = await call_next(request)
            hits = 0

        if response is None:
            response = await call_next(request)

        if inspected:
            sanitizer_events.labels(tenant, "multimodal").inc()

        if hits:
            response.headers["X-Guardrail-Sanitizer"] = f"multimodal;hits={hits}"
            action = flags.action
            if action == "clarify":
                response.headers["X-Guardrail-Mode"] = "clarify"
                sanitizer_actions.labels(tenant, "clarify").inc()
            elif action == "block":
                response.headers["X-Guardrail-Decision"] = "block-input"
                sanitizer_actions.labels(tenant, "block").inc()
            elif action == "flag":
                sanitizer_actions.labels(tenant, "flag").inc()
            else:
                sanitizer_actions.labels(tenant, "pass").inc()
        else:
            sanitizer_actions.labels(tenant, "pass").inc()

        return response
