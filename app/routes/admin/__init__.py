from __future__ import annotations

# This package exposes admin-related routers.
from .egress import router as egress_router

__all__ = ["egress_router"]
