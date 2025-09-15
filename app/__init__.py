# Make 'app' a proper package; re-export common entrypoints.
from __future__ import annotations
try:
    from .main import create_app  # noqa: F401
except Exception:
    # Don't fail package import just because factories can't import yet.
    pass
