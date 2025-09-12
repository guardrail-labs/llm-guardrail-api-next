from __future__ import annotations

import os
from typing import List

from app.services.bindings.models import Binding

_BINDINGS: List[Binding] = []


def APPLY_ENABLED() -> bool:
    return (os.getenv("ADMIN_ENABLE_APPLY") or "0").strip() in ("1", "true", "yes")


def get_bindings() -> List[Binding]:
    return list(_BINDINGS)


def set_bindings(bindings: List[Binding]) -> None:
    if not APPLY_ENABLED():
        return
    _BINDINGS.clear()
    _BINDINGS.extend(bindings)
