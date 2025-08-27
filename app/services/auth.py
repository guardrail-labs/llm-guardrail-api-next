from __future__ import annotations

import os
from fastapi import Request, HTTPException, status

# In CI/tests we set GUARDRAIL_DISABLE_AUTH=1 (see conftest.py)
DISABLE_AUTH = os.getenv("GUARDRAIL_DISABLE_AUTH") == "1"


def require_api_key(request: Request) -> None:
    """
    Simple header-based API key gate.

    - Bypassed when GUARDRAIL_DISABLE_AUTH=1 (tests/CI).
    - In prod, expects header X-API-Key to match GUARDRAIL_API_KEY.
    """
    if DISABLE_AUTH:
        return

    expected = os.getenv("GUARDRAIL_API_KEY")
    provided = request.headers.get("X-API-Key")

    if not expected or provided != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
