"""Runtime guard entrypoints with legacy compatibility."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Iterable

from .router import GuardedRouter, GuardResponse, get_default_router

__all__ = ["GuardResponse", "GuardedRouter", "get_default_router"]


def _load_legacy_runtime() -> None:
    legacy_path = Path(__file__).resolve().parent.parent / "runtime.py"
    if not legacy_path.exists():  # pragma: no cover - safety for refactors
        return

    spec = importlib.util.spec_from_file_location("app._runtime_legacy", legacy_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return

    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("app._runtime_legacy", module)
    spec.loader.exec_module(module)
    sys.modules.setdefault("app.runtime_legacy", module)

    exported: Iterable[str]
    if hasattr(module, "__all__"):
        exported = getattr(module, "__all__") or []
    else:  # pragma: no cover - legacy modules without __all__
        exported = [name for name in dir(module) if not name.startswith("_")]

    for name in exported:
        value: Any = getattr(module, name)
        globals().setdefault(name, value)
        if name not in __all__:
            __all__.append(name)


_load_legacy_runtime()

__all__ = sorted(__all__)
