from __future__ import annotations

from app.services import policy_store

PACK_ID = "secrets_strict"


def is_enabled(tenant: str, bot: str) -> bool:
    try:
        return bool(policy_store.is_bound(tenant=tenant, bot=bot, pack=PACK_ID))
    except Exception:
        return False


def set_enabled(tenant: str, bot: str, enabled: bool) -> None:
    if enabled:
        try:
            if not is_enabled(tenant, bot):
                policy_store.bind_pack(tenant=tenant, bot=bot, pack=PACK_ID)
        except AttributeError:
            policy_store.bind_pack(tenant=tenant, bot=bot, pack=PACK_ID)
    else:
        try:
            if is_enabled(tenant, bot):
                policy_store.unbind_pack(tenant=tenant, bot=bot, pack=PACK_ID)
        except AttributeError:
            pass
