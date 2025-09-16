# app/app.py
"""
Compatibility shim for tests or tools that import `from app.app import create_app`.
We re-export from the real entrypoint `app.main` using absolute imports to
avoid package-context issues.
"""
from __future__ import annotations

from app.main import app, create_app  # required
try:
    from app.main import build_app  # optional
except Exception:  # pragma: no cover
    build_app = None  # type: ignore[assignment]

__all__ = ["app", "build_app", "create_app"]
