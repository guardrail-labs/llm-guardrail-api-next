from __future__ import annotations

import json
from typing import Any, Callable, Dict, Tuple, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.metrics_sanitizer import sanitizer_actions, sanitizer_events
from app.policy import flags as policy_flags
from app.policy.flags import SanitizerFlags
from app.sanitizers.confusables import analyze_confusables, escape_confusables
from app.sanitizers.unicode import sanitize_unicode

JsonObj = Dict[str, Any]
JsonVal = Any


def _deep_map_str(val: JsonVal, fn: Callable[[str], str]) -> JsonVal:
    if isinstance(val, str):
        return fn(val)
    if isinstance(val, list):
        return [_deep_map_str(v, fn) for v in val]
    if isinstance(val, dict):
        return {k: _deep_map_str(v, fn) for k, v in val.items()}
    return val


def _collect_strings(data: JsonObj) -> str:
    concat: list[str] = []

    def _collect(s: str) -> str:
        concat.append(s)
        return s

    _deep_map_str(data, _collect)
    return " ".join(concat)


def _sanitize_with_flags(
    data: JsonObj,
    flags: SanitizerFlags,
    transform: Callable[[str], str] | None = None,
) -> JsonObj:
    def _sanitize_str(text: str) -> str:
        base = transform(text) if transform else text
        return sanitize_unicode(
            base,
            normalize=flags.enable_normalize,
            strip_zero_width=flags.strip_zero_width,
            escape_bidi=flags.escape_bidi,
        )

    return cast(JsonObj, _deep_map_str(data, _sanitize_str))


def _resolve_confusables_action(
    hits: int, ratio: float, flags: SanitizerFlags
) -> Tuple[str, bool]:
    threshold_met = hits > 0 and ratio >= flags.max_confusables_ratio
    if not threshold_met or flags.confusables_action == "off":
        return "pass", False
    action = flags.confusables_action
    if action in {"escape", "clarify", "block", "flag"}:
        return action, True
    return "flag", True


class UnicodeSanitizerMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ctype = request.headers.get("content-type", "")
        method = request.method.upper()
        is_json = "application/json" in ctype
        mutate = is_json and method in {"POST", "PUT", "PATCH"}

        tenant = policy_flags.get_tenant_id_from_headers(request.headers.get)
        flags = policy_flags.get_sanitizer_flags(tenant)

        if not mutate:
            return await call_next(request)

        try:
            raw = await request.body()
            if not raw:
                return await call_next(request)

            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return await call_next(request)

            joined = _collect_strings(data)
            report = analyze_confusables(joined)
            action, triggered = _resolve_confusables_action(
                report.confusable_count, report.ratio, flags
            )
            transform = escape_confusables if action == "escape" and triggered else None
            sanitized = _sanitize_with_flags(data, flags, transform)
            hits = report.confusable_count
            ratio = report.ratio

            sanitizer_events.labels(tenant, "unicode").inc()
            if hits:
                sanitizer_events.labels(tenant, "confusable").inc(hits)

            sanitizer_actions.labels(tenant, action).inc()

            new_body = json.dumps(sanitized, ensure_ascii=False).encode("utf-8")
            setattr(request, "_body", new_body)
            setattr(request, "_stream_consumed", True)

            response = await call_next(request)

            if action != "pass":
                response.headers["X-Guardrail-Sanitizer"] = (
                    f"confusables;ratio={ratio:.4f};hits={hits}"
                )
            if action == "clarify":
                response.headers["X-Guardrail-Mode"] = "clarify"
            if action == "block":
                response.headers["X-Guardrail-Decision"] = "block-input"

            return response
        except Exception:
            return await call_next(request)
