"""Image modality entrypoint."""

from __future__ import annotations

from typing import Any

from .router import GuardedRouter, GuardResponse, ModelCallable, get_default_router


async def handle_image(
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
        modality="image",
        request_id=request_id,
        payload=payload,
        model=model,
    )


__all__ = ["handle_image", "get_default_router"]
