"""Expose route modules so main app auto-includes them."""

# Import for side effects; routers are discovered via attribute inspection.
from . import (
    admin_runtime,  # noqa: F401
    egress_stream_demo,  # noqa: F401
    health,  # noqa: F401
)
