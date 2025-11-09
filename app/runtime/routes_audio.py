"""Audio modality entrypoint."""

from __future__ import annotations

from typing import Any

from .router import GuardedRouter, GuardResponse, ModelCallable, get_default_router


async def handle_audio(
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
        modality="audio",
        request_id=request_id,
        payload=payload,
        model=model,
    )


__all__ = ["handle_audio", "get_default_router"]
