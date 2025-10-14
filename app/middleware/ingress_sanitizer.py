from __future__ import annotations

from typing import Any, Awaitable, Callable

from app.sanitizers.unicode import sanitize_unicode

from .types import IngressRequest


async def sanitize_ingress_request(
    req: IngressRequest, next_handler: Callable[[IngressRequest], Awaitable[Any]]
) -> Any:
    """Apply ingress sanitization before classification and routing."""
    try:
        if hasattr(req, "text") and isinstance(req.text, str):
            req.text = sanitize_unicode(req.text)
        if hasattr(req, "messages") and isinstance(req.messages, list):
            sanitized_messages: list[Any] = []
            for message in req.messages:
                if isinstance(message, str):
                    sanitized_messages.append(sanitize_unicode(message))
                    continue
                if isinstance(message, dict):
                    updated = dict(message)
                    for key, value in list(updated.items()):
                        if isinstance(value, str):
                            updated[key] = sanitize_unicode(value)
                    sanitized_messages.append(updated)
                    continue
                sanitized_messages.append(message)
            req.messages = sanitized_messages
    except Exception:
        pass
    return await next_handler(req)
