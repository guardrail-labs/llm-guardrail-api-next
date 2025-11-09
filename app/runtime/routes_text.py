"""Text modality entrypoint for the guarded runtime."""

from __future__ import annotations

from typing import Any

from .router import GuardedRouter, GuardResponse, ModelCallable, get_default_router


async def handle_text(
    payload: Any,
    *,
    tenant: str,
    request_id: str,
    model: ModelCallable,
    router: GuardedRouter | None = None,
) -> GuardResponse:
    active_router = router or get_default_router()
    return await active_router.route(
        tenant=tenant,
        modality="text",
        request_id=request_id,
        payload=payload,
        model=model,
    )


__all__ = ["handle_text", "get_default_router"]
