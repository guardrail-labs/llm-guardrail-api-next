import hmac
from typing import List, Optional

from fastapi import Header, HTTPException
from app.config import Settings


def _configured_keys() -> List[str]:
    """
    Read keys at call-time so tests/CI can set env before each run.
    Supports either:
      - API_KEY=<single>
      - API_KEYS=<comma,separated,list>
    """
    s = Settings()  # fresh read from env each call
    keys: List[str] = []
    if s.API_KEYS:
        keys.extend([k.strip() for k in s.API_KEYS.split(",") if k.strip()])
    if s.API_KEY:
        keys.append(s.API_KEY.strip())
    return keys


def _extract_presented_key(
    x_api_key: Optional[str],
    authorization: Optional[str],
    bearer_prefix: str,
) -> Optional[str]:
    """
    Accept either:
      - X-API-Key: <key>
      - Authorization: Bearer <key>
    """
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()

    if authorization:
        auth = authorization.strip()
        if auth.lower().startswith(bearer_prefix.lower()):
            return auth[len(bearer_prefix) :].strip()

    return None


async def require_api_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    s = Settings()  # read prefix dynamically (supports future config)
    presented = _extract_presented_key(x_api_key, authorization, bearer_prefix=s.AUTH_BEARER_PREFIX)

    if not presented:
        raise HTTPException(status_code=401, detail="Missing API key")

    keys = _configured_keys()
    if not keys:
        # Misconfiguration: no keys on server
        raise HTTPException(status_code=500, detail="Server misconfigured: API key not set")

    for configured in keys:
        if hmac.compare_digest(presented, configured):
            return  # success

    raise HTTPException(status_code=401, detail="Invalid API key")
