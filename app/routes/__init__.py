"""Expose route modules so main app auto-includes them."""

# Import for side effects; routers are discovered via attribute inspection.
from . import health  # noqa: F401
