from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

_REDACT_CODE = os.getenv("LOCK_REDACT_CODE_BLOCKS", "true").lower() == "true"
_REDACT_URLS = os.getenv("LOCK_REDACT_URLS", "true").lower() == "true"
_REDACT_SECRETS = os.getenv("LOCK_REDACT_SECRETS", "true").lower() == "true"
_MAX_CHARS = int(os.getenv("LOCK_MAX_OUTPUT_CHARS", "2000"))

RX_CODEBLOCK = re.compile(r"```.*?```", re.S)
RX_URL = re.compile(r"https?://\S+", re.I)
RX_AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
RX_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=]+\b", re.I)
RX_PRIV_KEY = re.compile(
    r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END .*? PRIVATE KEY-----",
    re.S,
)


def _redact_text(text: str) -> str:
    result = text
    if _REDACT_CODE:
        result = RX_CODEBLOCK.sub("[redacted code]", result)
    if _REDACT_URLS:
        result = RX_URL.sub("[redacted url]", result)
    if _REDACT_SECRETS:
        result = RX_AWS_KEY.sub("[redacted key]", result)
        result = RX_BEARER.sub("Bearer [redacted]", result)
        result = RX_PRIV_KEY.sub("[redacted private key]", result)
    if len(result) > _MAX_CHARS:
        result = result[:_MAX_CHARS] + "…"
    return result


def _scrub_message_payload(payload: Dict[str, Any]) -> None:
    payload.pop("tool_calls", None)
    payload.pop("function_call", None)
    for key in ("text", "content", "message", "output"):
        value = payload.get(key)
        if isinstance(value, str):
            payload[key] = _redact_text(value)
        elif isinstance(value, list):
            payload[key] = [
                _redact_text(v) if isinstance(v, str) else v for v in value
            ]
        elif isinstance(value, dict):
            _scrub_message_payload(value)


def _scrub_choices(obj: Dict[str, Any]) -> None:
    choices = obj.get("choices")
    if not isinstance(choices, list):
        return
    for choice in choices:
        if isinstance(choice, dict):
            _scrub_message_payload(choice)
            message = choice.get("message")
            if isinstance(message, dict):
                _scrub_message_payload(message)
            delta = choice.get("delta")
            if isinstance(delta, dict):
                _scrub_message_payload(delta)


def _scrub_json_object(obj: Dict[str, Any]) -> Dict[str, Any]:
    _scrub_message_payload(obj)
    _scrub_choices(obj)
    return obj


def redact_response_body(body: bytes, content_type: str | None) -> bytes:
    content_type = (content_type or "").lower()
    if content_type and (
        "application/json" in content_type or content_type.endswith("+json")
    ):
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            scrubbed = _scrub_json_object(parsed)
            return json.dumps(scrubbed, ensure_ascii=False).encode("utf-8")
        if parsed is not None:
            try:
                textified = json.dumps(parsed, ensure_ascii=False)
            except Exception:
                textified = body.decode("utf-8", errors="replace")
            return _redact_text(textified).encode("utf-8")
        try:
            text = body.decode("utf-8", errors="replace")
            return _redact_text(text).encode("utf-8")
        except Exception:
            return body
    if content_type.startswith("text/"):
        try:
            return _redact_text(body.decode("utf-8", errors="replace")).encode(
                "utf-8"
            )
        except Exception:
            return body
    return body
