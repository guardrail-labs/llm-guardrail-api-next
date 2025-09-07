from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="Audit Receiver")


# ----------------------------- config ----------------------------------------


def _truthy(v: Optional[str]) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


API_KEY = os.getenv("AUDIT_RECEIVER_API_KEY", "")
SIGNING_SECRET = os.getenv("AUDIT_RECEIVER_SIGNING_SECRET", "")
REQUIRE_SIG = _truthy(
    os.getenv("AUDIT_RECEIVER_REQUIRE_SIGNATURE", "1" if SIGNING_SECRET else "0")
)
ENFORCE_TS = _truthy(os.getenv("AUDIT_RECEIVER_ENFORCE_TS", "1"))
TS_SKEW_SEC = int(os.getenv("AUDIT_RECEIVER_TS_SKEW_SEC", "300"))  # ±5min default

# Idempotency key TTL (seconds).
IDEMP_TTL = max(1, int(os.getenv("AUDIT_RECEIVER_IDEMP_TTL_SEC", "60")))


# ----------------------------- idempotency store ------------------------------


# Simple in-memory TTL cache: key -> expires_at (epoch seconds).
_IDEMP: Dict[str, int] = {}


def _now() -> int:
    return int(time.time())


def _prune(now: int) -> None:
    if not _IDEMP:
        return
    drop = [k for k, exp in _IDEMP.items() if exp <= now]
    for k in drop:
        _IDEMP.pop(k, None)


def _mark_or_seen(key: str, ttl: int) -> bool:
    """
    Returns True if key is a *repeat* (seen and not expired).
    Otherwise marks it with new expiry and returns False.
    """
    now = _now()
    _prune(now)
    exp = _IDEMP.get(key)
    if exp and exp > now:
        return True
    _IDEMP[key] = now + max(1, ttl)
    return False


# ----------------------------- signing verify --------------------------------


def _compare_digest(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


def _verify_hmac(
    raw_body: bytes,
    header_sig: Optional[str],
    header_ts: Optional[str],
) -> None:
    if not REQUIRE_SIG:
        return

    if not SIGNING_SECRET:
        raise HTTPException(
            status_code=500, detail="Signing required but secret not set"
        )

    if not header_sig:
        raise HTTPException(status_code=401, detail="Missing signature")

    if not header_ts:
        raise HTTPException(status_code=401, detail="Missing signature timestamp")

    # Timestamp checks first (freshness)
    try:
        sent = int(header_ts)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Malformed signature timestamp"
        )

    if ENFORCE_TS:
        now = _now()
        if abs(now - sent) > TS_SKEW_SEC:
            raise HTTPException(
                status_code=401, detail="Stale signature timestamp"
            )

    # Expected: HMAC(secret, ts + "." + body)
    msg = header_ts.encode("utf-8") + b"." + raw_body
    expected = hmac.new(
        SIGNING_SECRET.encode("utf-8"), msg, hashlib.sha256
    ).hexdigest()
    presented = header_sig.split("=", 1)[-1].strip()

    if not _compare_digest(expected, presented):
        raise HTTPException(status_code=401, detail="Bad signature")


# ----------------------------- route -----------------------------------------


@app.post("/audit")
async def receive_audit(
    request: Request,
    x_api_key: Optional[str] = Header(
        default=None, alias="X-API-Key", convert_underscores=False
    ),
    x_signature: Optional[str] = Header(
        default=None, alias="X-Signature", convert_underscores=False
    ),
    x_signature_ts: Optional[str] = Header(
        default=None, alias="X-Signature-Ts", convert_underscores=False
    ),
    x_idempotency_key: Optional[str] = Header(
        default=None, alias="X-Idempotency-Key", convert_underscores=False
    ),
) -> Dict[str, Any]:
    # API key gate (optional)
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    raw = await request.body()

    # HMAC + timestamp
    _verify_hmac(raw, x_signature, x_signature_ts)

    # Validate payload before consuming idempotency key
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Only now record/mark idempotency; repeats are deduped within TTL
    deduped = False
    if x_idempotency_key:
        deduped = _mark_or_seen(x_idempotency_key, IDEMP_TTL)

    return {
        "ok": True,
        "received": bool(payload),
        "deduped": bool(deduped),
        "idempotency": x_idempotency_key,
    }
