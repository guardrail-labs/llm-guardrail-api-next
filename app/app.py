"""
Compatibility shim so `from app.main import create_app` (tests) and
`uvicorn app.main:create_app` (runtime) both work under pytest and normal runs.

We prefer an absolute import (package context). If that isn't available, fall
back to a relative import (when executed inside the package).
"""
from __future__ import annotations

try:
    # Works when repo root is on sys.path (pytest default)
    from app.main import app, build_app, create_app  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    # Fallback for rare cases where module is executed in-package
    from .main import app, build_app, create_app  # type: ignore[attr-defined]

__all__ = ["app", "build_app", "create_app"]
