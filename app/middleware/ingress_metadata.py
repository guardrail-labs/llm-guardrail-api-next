from __future__ import annotations

import json
import re
from typing import Any, Awaitable, Callable, Dict, List, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import metadata_ingress_report
from app.sanitizers.metadata import sanitize_filename, sanitize_header_value

# Header names
_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"

# Common JSON hints where filenames appear
_FILENAME_KEYS = {"filename", "file_name", "upload_filename", "original_filename"}

# Content-Disposition filename* (RFC 5987) or filename=
_CD_FILENAME_RE = re.compile(
    r'filename\*?=(?:"?)([^";\r\n]+)',
    flags=re.IGNORECASE,
)


def _sanitize_scope_headers(
    raw: List[Tuple[bytes, bytes]],
) -> Tuple[List[Tuple[bytes, bytes]], int, int, int, str, str]:
    """
    Sanitize headers using scope-level list to avoid Headers cache issues.
    Returns (new_headers, headers_changed, filenames_sanitized, truncated,
             tenant, bot) where tenant/bot are taken from sanitized values.
    """
    headers_changed = 0
    filenames_sanitized = 0
    truncated = 0
    tenant = ""
    bot = ""

    new_headers: List[Tuple[bytes, bytes]] = []
    for kb, vb in raw or []:
        key = kb.decode("latin-1")
        val = vb.decode("latin-1")

        sval, hst = sanitize_header_value(val)
        if hst.get("truncated", 0):
            truncated += 1
        if hst.get("changed", 0):
            headers_changed += 1

        # Content-Disposition filename handling
        if key.lower() == "content-disposition":

            def _fix_filename(m: re.Match[str]) -> str:
                fname = m.group(1)
                safe, fst = sanitize_filename(fname)
                nonlocal filenames_sanitized, truncated
                filenames_sanitized += 1
                truncated += fst.get("truncated", 0)
                return f'filename="{safe}"'

            sval = _CD_FILENAME_RE.sub(_fix_filename, sval)

        # Capture tenant/bot from sanitized values
        lower_key = key.lower()
        if lower_key == _HDR_TENANT.lower():
            tenant = sval
        elif lower_key == _HDR_BOT.lower():
            bot = sval

        new_headers.append((key.encode("latin-1"), sval.encode("latin-1")))

    return new_headers, headers_changed, filenames_sanitized, truncated, tenant, bot


class IngressMetadataMiddleware(BaseHTTPMiddleware):
    """
    Scrub suspicious metadata in headers and JSON hints:
      - Sanitize all header values via Unicode sanitizer + length bounds
      - Extract and sanitize filenames from Content-Disposition
      - Sanitize common filename fields in JSON bodies
    Emits Prometheus counters.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        # Sanitize scope-level headers BEFORE accessing request.headers
        raw_headers = list(request.scope.get("headers", []))
        (
            scope_headers,
            headers_changed,
            filenames_sanitized,
            truncated,
            tenant,
            bot,
        ) = _sanitize_scope_headers(raw_headers)

        if headers_changed or filenames_sanitized or truncated:
            request.scope["headers"] = scope_headers
            # Invalidate cached Headers so downstream sees sanitized values:
            # delete the attribute (do NOT set to None).
            if hasattr(request, "_headers"):
                delattr(request, "_headers")

        # Safe to access request.headers now
        ctype = request.headers.get("content-type", "").lower()
        if "application/json" in ctype:
            raw = await request.body()
            if raw:
                try:
                    data = json.loads(raw)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    touched = 0

                    def _walk(obj):
                        nonlocal touched, filenames_sanitized, truncated
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if (
                                    isinstance(k, str)
                                    and k.lower() in _FILENAME_KEYS
                                    and isinstance(v, str)
                                ):
                                    safe, fst = sanitize_filename(v)
                                    if safe != v or fst.get("truncated", 0):
                                        obj[k] = safe
                                        touched += 1
                                        filenames_sanitized += 1
                                        truncated += fst.get("truncated", 0)
                                else:
                                    _walk(v)
                        elif isinstance(obj, list):
                            for it in obj:
                                _walk(it)

                    _walk(data)
                    if touched:
                        new_body = json.dumps(data).encode("utf-8")

                        async def receive() -> Dict[str, Any]:
                            return {
                                "type": "http.request",
                                "body": new_body,
                                "more_body": False,
                            }

                        request = Request(request.scope, receive)

        # If tenant/bot are still empty, it's fine; label limiter will bucket
        metadata_ingress_report(
            tenant=tenant,
            bot=bot,
            headers_changed=headers_changed,
            filenames_sanitized=filenames_sanitized,
            truncated=truncated,
        )

        return await call_next(request)
