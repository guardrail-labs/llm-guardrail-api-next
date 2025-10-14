from __future__ import annotations

import json
from typing import Any, Dict, List, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.sanitizers.unicode import sanitize_unicode

JsonObj = Dict[str, Any]
JsonVal = Any


def _sanitize_json_val(val: JsonVal) -> JsonVal:
    if isinstance(val, str):
        return sanitize_unicode(val)
    if isinstance(val, list):
        return [_sanitize_json_val(v) for v in val]
    if isinstance(val, dict):
        return {k: _sanitize_json_val(v) for k, v in val.items()}
    return val


def _sanitize_payload(data: JsonObj) -> JsonObj:
    if "text" in data and isinstance(data["text"], str):
        data["text"] = sanitize_unicode(data["text"])
    if "messages" in data and isinstance(data["messages"], list):
        msgs: List[Any] = []
        for msg in data["messages"]:
            msgs.append(_sanitize_json_val(msg))
        data["messages"] = msgs
    sanitized = cast(JsonObj, _sanitize_json_val(data))
    return sanitized


class UnicodeSanitizerMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ctype = request.headers.get("content-type", "")
        method = request.method.upper()
        is_json = "application/json" in ctype
        mutate = is_json and method in {"POST", "PUT", "PATCH"}

        if not mutate:
            return await call_next(request)

        try:
            raw = await request.body()
            if not raw:
                return await call_next(request)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return await call_next(request)
            sanitized = _sanitize_payload(data)
            new_body = json.dumps(sanitized, ensure_ascii=False).encode("utf-8")
            setattr(request, "_body", new_body)
            setattr(request, "_stream_consumed", True)
            return await call_next(request)
        except Exception:
            # Fail-closed for the sanitizer only: do not block the request path.
            return await call_next(request)
