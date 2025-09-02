from __future__ import annotations

import os
from typing import Any, Dict, List

from fastapi import APIRouter

from app.services import threat_feed as tf

router = APIRouter(prefix="/admin/threat", tags=["admin"])


@router.post("/reload")
def reload_threat_feeds() -> Dict[str, Any]:
    """
    Contract expected by tests:
      200 OK with: {"ok": true, "result": {"compiled": <int>}}
    Loads rules from THREAT_FEED_URLS (comma-separated) using tf._fetch_json
    and activates them for dynamic redaction.
    """
    urls_env = os.environ.get("THREAT_FEED_URLS", "") or ""
    urls: List[str] = [u.strip() for u in urls_env.split(",") if u.strip()]
    if not urls:
        return {"ok": True, "result": {"compiled": 0}}

    compiled = tf.reload_from_urls(urls)
    return {"ok": True, "result": {"compiled": compiled}}
