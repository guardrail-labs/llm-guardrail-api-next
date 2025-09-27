from __future__ import annotations

import unicodedata as ud
from collections.abc import Iterable
from urllib.parse import unquote_plus

from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.middleware.ingress_trace_guard import _tenant_bot_from_headers
from app.observability.metrics import unicode_blocked, unicode_flagged
from app.services.config_store import get_config

_ZWC = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u2060",
    "\u180e",
}

_BIDI = {
    "\u202a",
    "\u202b",
    "\u202d",
    "\u202e",
    "\u202c",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200e",
    "\u200f",
}

_CONF_MAP = {
    "\u0430": "a",
    "\u0441": "c",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0445": "x",
    "\u0443": "y",
    "\u043a": "k",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u0442": "t",
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c7": "x",
    "\u03c5": "y",
    "\u039f": "O",
    "\u03a1": "P",
}

_EMOJI_RANGES = (
    (0x1F300, 0x1F5FF),
    (0x1F600, 0x1F64F),
    (0x1F680, 0x1F6FF),
    (0x1F700, 0x1F77F),
    (0x1F900, 0x1F9FF),
    (0x1FA70, 0x1FAFF),
    (0x1F1E6, 0x1F1FF),
    (0x2600, 0x27BF),
)


def _to_int(value: object) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int | float):
            return int(value)
        return int(str(value).strip())
    except Exception:
        return 0


def _normalize(sample: str) -> str:
    try:
        return ud.normalize("NFKC", sample)
    except Exception:
        return sample


def _skeleton(sample: str) -> str:
    mapped = "".join(_CONF_MAP.get(char, char) for char in sample)
    return "".join(char for char in mapped if ud.combining(char) == 0)


def _script(char: str) -> str:
    name = ud.name(char, "")
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "GREEK" in name:
        return "Greek"
    if "LATIN" in name:
        return "Latin"
    return "Other"


def _is_emoji(char: str) -> bool:
    codepoint = ord(char)
    for start, end in _EMOJI_RANGES:
        if start <= codepoint <= end:
            return True
    return False


def _scan(raw: str, normalized: str) -> dict[str, bool]:
    flags: dict[str, bool] = {}
    flags["zwc"] = any(char in _ZWC for char in raw)
    flags["bidi"] = any(char in _BIDI for char in raw)
    flags["emoji"] = any(_is_emoji(char) for char in raw)
    skel_raw = _skeleton(raw)
    flags["confusables"] = skel_raw != raw or normalized != raw
    scripts = {_script(char) for char in raw if char.isalpha()}
    flags["mixed"] = len({"Latin", "Cyrillic", "Greek"}.intersection(scripts)) >= 2
    return flags


def _sample_headers(headers: Iterable[tuple[bytes, bytes]], cap_bytes: int) -> str:
    if cap_bytes <= 0:
        return ""
    parts: list[str] = []
    used = 0
    for _, value in headers:
        if used >= cap_bytes:
            break
        remaining = cap_bytes - used
        chunk = value[:remaining]
        if not chunk:
            continue
        text = chunk.decode("utf-8", "ignore")
        if text:
            parts.append(text)
        used += len(chunk)
    return " ".join(parts)


class IngressUnicodeSanitizerMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        config = get_config()
        if not bool(config.get("ingress_unicode_sanitizer_enabled", False)):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        path_cap = max(_to_int(config.get("ingress_unicode_path_sample_chars", 1024)), 0)
        query_cap = max(_to_int(config.get("ingress_unicode_query_sample_bytes", 4096)), 0)
        header_cap = max(
            _to_int(config.get("ingress_unicode_header_sample_bytes", 4096)),
            0,
        )

        root_path = scope.get("root_path", "") or ""
        raw_path = scope.get("path", "") or ""
        path_sample = (root_path + raw_path)[:path_cap] if path_cap else ""

        query_bytes = (scope.get("query_string") or b"")[:query_cap]
        if query_bytes:
            raw_query = query_bytes.decode("utf-8", "ignore")
            try:
                query_sample = unquote_plus(raw_query)
            except Exception:
                query_sample = raw_query
        else:
            query_sample = ""

        headers: Iterable[tuple[bytes, bytes]] = scope.get("headers") or ()
        header_sample = _sample_headers(headers, header_cap)

        sample_parts = [part for part in (path_sample, query_sample, header_sample) if part]
        sample = " ".join(sample_parts)

        normalized = _normalize(sample)
        skeleton = _skeleton(sample)
        flags = _scan(sample, normalized)
        active_flags = {name for name, enabled in flags.items() if enabled}
        flag_header_value = ",".join(sorted(active_flags))

        scope.setdefault("state", {})
        unicode_state = {
            "normalized": normalized,
            "skeleton": skeleton,
            "flags": set(active_flags),
        }
        setattr(request.state, "unicode", unicode_state)

        allowed_flags = {"bidi", "zwc", "emoji", "confusables", "mixed"}
        mode_raw = config.get("ingress_unicode_enforce_mode", "off")
        mode = str(mode_raw or "off").strip().lower()
        if mode not in {"off", "log", "block"}:
            mode = "off"

        raw_enforce = config.get("ingress_unicode_enforce_flags", ["bidi", "zwc"])
        enforce_flags: set[str] = set()
        if isinstance(raw_enforce, str):
            tokens = [s.strip().lower() for s in raw_enforce.split(",") if s.strip()]
            enforce_flags = {token for token in tokens if token in allowed_flags}
        elif isinstance(raw_enforce, list | tuple | set):
            tokens = [str(item).strip().lower() for item in raw_enforce if str(item).strip()]
            enforce_flags = {token for token in tokens if token in allowed_flags}

        hit = sorted(enforce_flags.intersection(active_flags))
        audit_header: bytes | None = None
        if hit:
            tenant, bot = _tenant_bot_from_headers(request)
            for flag_name in hit:
                unicode_flagged.labels(tenant=tenant, bot=bot, mode=mode, flag=flag_name).inc()

            if mode == "block":
                for flag_name in hit:
                    unicode_blocked.labels(tenant=tenant, bot=bot, flag=flag_name).inc()
                response = PlainTextResponse(
                    "Blocked: risky unicode in request metadata", status_code=400
                )
                flags_value = ",".join(hit)
                response.headers["X-Guardrail-Unicode-Blocked"] = f"flags={flags_value}"
                response.headers["X-Guardrail-Ingress-Flags"] = flag_header_value
                response.headers["Connection"] = "close"
                await response(scope, receive, send)
                return

            if mode == "log":
                audit_header = f"flags={','.join(hit)}".encode()

        async def send_wrapper(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers_list = list(message.get("headers") or [])
                headers_list.append(
                    (
                        b"x-guardrail-ingress-flags",
                        flag_header_value.encode("utf-8"),
                    )
                )
                if audit_header is not None:
                    headers_list.append(
                        (
                            b"x-guardrail-unicode-audit",
                            audit_header,
                        )
                    )
                message["headers"] = headers_list
            await send(message)

        await self.app(scope, receive, send_wrapper)
