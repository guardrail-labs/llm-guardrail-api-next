from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="Audit Receiver")

# --- Env/config helpers ------------------------------------------------------


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _getenv(name: str, default: str = "") -> str:
    import os
    return os.getenv(name, default)


REQUIRE_KEY = _truthy(_getenv("AUDIT_RECEIVER_REQUIRE_API_KEY", "0"))
API_KEY = _getenv("AUDIT_RECEIVER_API_KEY", "")

REQUIRE_SIG = _truthy(_getenv("AUDIT_RECEIVER_REQUIRE_SIGNATURE", "0"))
ENFORCE_TS = _truthy(_getenv("AUDIT_RECEIVER_ENFORCE_TS", "0"))
TS_SKEW_SEC = int(_getenv("AUDIT_RECEIVER_TS_SKEW_SEC", "300") or "300")

SECRET_PRIMARY = _getenv("AUDIT_RECEIVER_SIGNING_SECRET", "")
SECRET_SECONDARY = _getenv("AUDIT_RECEIVER_SIGNING_SECRET_SECONDARY", "")

IDEMP_TTL = int(_getenv("AUDIT_RECEIVER_IDEMP_TTL_SEC", "60") or "60")

# In-memory idempotency set for example purposes only.
_IDEMP: Dict[str, float] = {}


def _mark_or_seen(key: str, ttl_sec: int) -> bool:
    now = time.time()
    # Clean out expired entries.
    expired = [k for k, v in _IDEMP.items() if v <= now]
    for k in expired:
        _IDEMP.pop(k, None)
    if key in _IDEMP:
        return True
    _IDEMP[key] = now + ttl_sec
    return False


def _decompress_if_needed(raw: bytes, encoding: Optional[str]) -> bytes:
    if (encoding or "").lower() == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            return gz.read()
    return raw


def _verify_signature(
    body_json_bytes: bytes,
    header_sig: Optional[str],
    header_ts: Optional[str],
) -> None:
    if REQUIRE_SIG and not SECRET_PRIMARY:
        raise HTTPException(status_code=500, detail="Signing required but no secret")

    if not REQUIRE_SIG:
        return

    if ENFORCE_TS and not header_ts:
        raise HTTPException(status_code=401, detail="Missing signature timestamp")

    if not header_sig or not header_sig.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing or malformed signature")

    try:
        sent = int(header_ts or "0")
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed signature timestamp")

    if ENFORCE_TS:
        now = int(time.time())
        if abs(now - sent) > TS_SKEW_SEC:
            raise HTTPException(status_code=401, detail="Stale signature timestamp")

    msg = (header_ts or "").encode("utf-8") + b"." + body_json_bytes
    expect_hex_primary = hmac.new(
        SECRET_PRIMARY.encode("utf-8"), msg, hashlib.sha256
    ).hexdigest()

    provided = header_sig.split("=", 1)[1].strip().lower()
    if hmac.compare_digest(provided, expect_hex_primary):
        return

    if SECRET_SECONDARY:
        expect_hex_secondary = hmac.new(
            SECRET_SECONDARY.encode("utf-8"), msg, hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(provided, expect_hex_secondary):
            return

    raise HTTPException(status_code=401, detail="Signature verification failed")


class Ack(BaseModel):
    ok: bool
    deduped: bool = False


@app.get("/")
async def root() -> Dict[str, Any]:
    return {"ok": True}


@app.post("/audit", response_model=Ack)
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
) -> Ack:
    if REQUIRE_KEY and (x_api_key or "") != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Read and normalize body (handle gzip).
    raw = await request.body()
    body_bytes = _decompress_if_needed(raw, request.headers.get("Content-Encoding"))

    # Signature & timestamp enforcement occurs BEFORE any idempotency changes.
    _verify_signature(body_bytes, x_signature, x_signature_ts)

    # Parse JSON.
    try:
        _payload = json.loads(body_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Idempotency check AFTER full validation (safe for client retries).
    if x_idempotency_key:
        if _mark_or_seen(x_idempotency_key, IDEMP_TTL):
            # Example sink: 200 with dedup flag (keeps tests simple).
            return Ack(ok=True, deduped=True)

    # ... persist payload / enqueue / etc. (omitted in example)

    return Ack(ok=True, deduped=False)
