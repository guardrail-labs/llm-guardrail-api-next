"""
Import shim so both `from app.main import create_app` (tests) and
`uvicorn app.main:create_app` (runtime) work — even if PYTHONPATH is odd
and Python tries to import this file as a top-level module.

It first tries a normal absolute import. If that fails, it loads
`main.py` from this directory via importlib (no relative imports).
"""
from __future__ import annotations

from importlib import import_module, util as _import_util
from pathlib import Path
from types import ModuleType

# Public re-exports
app = None  # type: ignore[assignment]
build_app = None  # type: ignore[assignment]
create_app = None  # type: ignore[assignment]

def _load_from_app_package() -> ModuleType | None:
    try:
        return import_module("app.main")
    except Exception:
        return None

def _load_from_this_dir() -> ModuleType:
    here = Path(__file__).resolve().parent
    main_path = here / "main.py"
    spec = _import_util.spec_from_file_location("app_main_fallback", main_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load main.py from {main_path}")
    mod = _import_util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod

_mod = _load_from_app_package() or _load_from_this_dir()

# Bind expected symbols (raise clear error if missing)
try:
    app = getattr(_mod, "app")
except AttributeError as e:
    raise ImportError("`app.main` must define `app`") from e

try:
    build_app = getattr(_mod, "build_app")
except AttributeError:
    # optional in some repos; leave as None if not present
    build_app = None  # type: ignore[assignment]

try:
    create_app = getattr(_mod, "create_app")
except AttributeError as e:
    raise ImportError("`app.main` must define `create_app`") from e

__all__ = ["app", "build_app", "create_app"]
