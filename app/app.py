"""
Re-export entrypoints from app.main in a package-safe way.
No file-loader fallbacks; keeps absolute imports inside app.main working.
"""
from __future__ import annotations

from app.main import app, create_app  # required
try:
    from app.main import build_app     # optional in some repos
except Exception:  # pragma: no cover
    build_app = None  # type: ignore[assignment]

__all__ = ["app", "build_app", "create_app"]
