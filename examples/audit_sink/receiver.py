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
REQUIRE_SIG = _truthy(os.getenv("AUDIT_RECEIVER_REQUIRE_SIG", "1" if SIGNING_SECRET else "0"))
ENFORCE_TS = _truthy(os.getenv("AUDIT_RECEIVER_ENFORCE_TS", "1"))
TS_SKEW_SEC = int(os.getenv("AUDIT_RECEIVER_TS_SKEW_SEC", "300"))  # ±5min default


def _compare_digest(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


def _verify_hmac(raw_body: bytes, header_sig: Optional[str], header_ts: Optional[str]) -> None:
    if not REQUIRE_SIG:
        return

    if not SIGNING_SECRET:
        raise HTTPException(status_code=500, detail="Signing required but secret not set")

    if not header_sig:
        raise HTTPException(status_code=401, detail="Missing signature")

    if not header_ts:
        raise HTTPException(status_code=401, detail="Missing signature timestamp")

    # Timestamp checks first (freshness)
    try:
        sent = int(header_ts)
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed signature timestamp")

    if ENFORCE_TS:
        now = int(time.time())
        if abs(now - sent) > TS_SKEW_SEC:
            raise HTTPException(status_code=401, detail="Stale signature timestamp")

    # Expected: HMAC(secret, ts + "." + body)
    msg = header_ts.encode("utf-8") + b"." + raw_body
    expected = hmac.new(SIGNING_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    presented = header_sig.split("=", 1)[-1].strip()

    if not _compare_digest(expected, presented):
        raise HTTPException(status_code=401, detail="Bad signature")


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

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # TODO: add idempotency storage if needed (x_idempotency_key)
    # For now, just echo.
    return {"ok": True, "received": bool(payload), "idempotency": x_idempotency_key}
