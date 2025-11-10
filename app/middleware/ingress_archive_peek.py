from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.archives.peek import try_b64_archive
from app.observability.metrics import archive_ingress_report

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"

# Heuristic JSON shapes we support:
#  - {"filename": "foo.zip", "content_base64": "..."}
#  - {"file_name": "...", "content_b64": "..."}
#  - within lists and nested dicts.
_NAME_KEYS = {"filename", "file_name"}
_B64_KEYS = {"content_base64", "content_b64", "data_base64"}


def _walk_candidates(obj) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        # Find sibling name + base64 pairs
        names: List[str] = []
        b64s: List[str] = []
        for k, v in obj.items():
            kl = k.casefold() if isinstance(k, str) else k
            if isinstance(v, str) and isinstance(kl, str):
                if kl in _NAME_KEYS:
                    names.append(v)
                if kl in _B64_KEYS:
                    b64s.append(v)
        for n in names:
            for b in b64s:
                out.append((n, b))
        # Recurse
        for v in obj.values():
            out.extend(_walk_candidates(v))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(_walk_candidates(it))
    return out


class IngressArchivePeekMiddleware(BaseHTTPMiddleware):
    """
    Find small base64-encoded archives in JSON payloads and extract:
      - file name listing
      - text samples from texty files
    Does not mutate the payload. Adds strings to
      request.state.guardrail_plaintexts (scanner-friendly).
    Emits Prometheus metrics.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        ctype = request.headers.get("content-type", "").casefold()
        raw = None

        total_candidates = 0
        archives_detected = 0
        filenames_total = 0
        samples_total = 0
        nested_blocked = 0
        errors_total = 0

        if "application/json" in ctype:
            raw = await request.body()
            if raw:
                try:
                    data = json.loads(raw)
                except Exception:
                    data = None
                if data is not None:
                    pairs = _walk_candidates(data)
                    total_candidates = len(pairs)
                    derived: List[str] = []
                    for fname, b64 in pairs:
                        fnames, texts, st = try_b64_archive(fname, b64)
                        if fnames or texts:
                            archives_detected += 1
                        filenames_total += len(fnames)
                        samples_total += len(texts)
                        nested_blocked += st.get("nested_blocked", 0)
                        errors_total += st.get("errors", 0)

                        # Expose derived plaintext:
                        # - file listing (one line)
                        # - each text sample
                        if fnames:
                            derived.append(f"[archive:{fname}] files=" + ", ".join(fnames[:10]))
                        for t in texts:
                            if t:
                                derived.append(t)

                    if derived:
                        # Attach or extend the plaintexts bucket
                        existing = getattr(
                            request.state,
                            "guardrail_plaintexts",
                            [],
                        )
                        setattr(
                            request.state,
                            "guardrail_plaintexts",
                            list(existing) + derived,
                        )

        # Replay body if consumed
        if raw is not None:

            async def receive() -> Dict[str, Any]:
                return {"type": "http.request", "body": raw, "more_body": False}

            request = Request(request.scope, receive)

        archive_ingress_report(
            tenant=tenant,
            bot=bot,
            candidates=total_candidates,
            archives_detected=archives_detected,
            filenames=filenames_total,
            text_samples=samples_total,
            nested_blocked=nested_blocked,
            errors=errors_total,
        )

        return await call_next(request)
