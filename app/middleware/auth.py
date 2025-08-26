import hmac
from typing import List, Optional

from fastapi import Header, HTTPException
from app.config import settings


def _configured_keys() -> List[str]:
    """
    Collect configured API keys from either API_KEYS (comma-separated) or API_KEY (single).
    """
    keys: List[str] = []
    if settings.API_KEYS:
        keys.extend([k.strip() for k in settings.API_KEYS.split(",") if k.strip()])
    if settings.API_KEY:
        keys.append(settings.API_KEY.strip())
    return keys


def _extract_presented_key(x_api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    """
    Extract presented credential from either:
      - X-API-Key: <key>
      - Authorization: Bearer <key>
    """
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()

    if authorization:
        auth = authorization.strip()
        prefix = settings.AUTH_BEARER_PREFIX
        if auth.lower().startswith(prefix.lower()):
            return auth[len(prefix):].strip()

    return None


async def require_api_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    """
    FastAPI dependency that enforces a valid API key.
    - Returns 401 on missing/invalid key.
    - Returns 500 if the server is misconfigured (no keys configured).
    """
    presented = _extract_presented_key(x_api_key, authorization)
    if not presented:
        raise HTTPException(status_code=401, detail="Missing API key")

    keys = _configured_keys()
    if not keys:
        # Misconfiguration: no keys configured on the server
        raise HTTPException(status_code=500, detail="Server misconfigured: API key not set")

    for configured in keys:
        if hmac.compare_digest(presented, configured):
            return  # success

    raise HTTPException(status_code=401, detail="Invalid API key")
