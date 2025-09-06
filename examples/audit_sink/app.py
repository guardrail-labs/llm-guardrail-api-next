from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="Audit Receiver Example")
log = logging.getLogger("audit-receiver")
logging.basicConfig(level=logging.INFO)


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


# --- Config via env -----------------------------------------------------------

API_KEY = os.getenv("AUDIT_RECEIVER_API_KEY", "")  # optional
SIGNING_SECRET = os.getenv("AUDIT_RECEIVER_SIGNING_SECRET", "")  # optional
REQUIRE_SIGNATURE = _truthy(os.getenv("AUDIT_RECEIVER_REQUIRE_SIGNATURE", "0"))
IDEMP_TTL_SEC = max(1, int(os.getenv("AUDIT_RECEIVER_IDEMP_TTL_SEC", "600")))
IDEMP_MAX_KEYS = max(100, int(os.getenv("AUDIT_RECEIVER_MAX_KEYS", "10000")))
ENFORCE_TS = _truthy(os.getenv("AUDIT_RECEIVER_ENFORCE_TS", "0"))
TS_SKEW_SEC = max(0, int(os.getenv("AUDIT_RECEIVER_TS_SKEW_SEC", "600")))

# Signature scheme (must match forwarder):
#   X-Signature = "sha256=" + HMAC_SHA256(secret, f"{X-Signature-Ts}.{raw_json_body}")


# --- Simple TTL idempotency set ----------------------------------------------

class TTLIdemSet:
    """
    In-memory TTL cache for idempotency keys.
    add(key) -> True if new, False if duplicate (and not expired).
    """
    def __init__(self, ttl: int, capacity: int) -> None:
        self.ttl = ttl
        self.capacity = capacity
        self._store: "OrderedDict[str, float]" = OrderedDict()

    def _purge(self, now: float) -> None:
        while self._store:
            _, exp = next(iter(self._store.items()))
            if exp > now:
                break
            self._store.popitem(last=False)

    def add(self, key: str, now: Optional[float] = None) -> bool:
        now = now or time.time()
        self._purge(now)
        if key in self._store:
            if self._store[key] > now:
                return False
            self._store.pop(key, None)

        if len(self._store) >= self.capacity:
            self._store.popitem(last=False)

        self._store[key] = now + self.ttl
        return True


IDEMP_SET = TTLIdemSet(IDEMP_TTL_SEC, IDEMP_MAX_KEYS)


# --- Helpers ------------------------------------------------------------------

def _verify_api_key(header_val: Optional[str]) -> None:
    if not API_KEY:
        return
    if not header_val or header_val != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _verify_signature(
    raw_body: bytes,
    header_sig: Optional[str],
    header_ts: Optional[str],
) -> None:
    """
    If signatures are required (SIGNING_SECRET set OR REQUIRE_SIGNATURE=1):
      - Require X-Signature
      - If ENFORCE_TS=1, require X-Signature-Ts and check freshness
      - Verify HMAC over f"{ts}.{raw_body}". If a ts header is present but
        ENFORCE_TS=0, still bind the signature to that ts value.
    """
    require_sig = bool(SIGNING_SECRET) or REQUIRE_SIGNATURE
    if not require_sig:
        return

    if not SIGNING_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Receiver requires signatures but no signing secret is set",
        )

    if not header_sig:
        raise HTTPException(status_code=401, detail="Missing signature")

    # Decide which timestamp string to bind in HMAC. When ENFORCE_TS=1, require &
    # validate freshness. When ENFORCE_TS=0, use header if provided; otherwise bind "".
    ts_str = ""
    if header_ts:
        try:
            ts_int = int(header_ts)
            ts_str = header_ts
        except ValueError:
            if ENFORCE_TS:
                raise HTTPException(status_code=400, detail="Malformed signature timestamp")
            # ignore bad ts when not enforcing; treat as absent
            ts_str = ""
        else:
            if ENFORCE_TS and TS_SKEW_SEC and abs(int(time.time()) - ts_int) > TS_SKEW_SEC:
                raise HTTPException(status_code=401, detail="Stale signature timestamp")
    else:
        if ENFORCE_TS:
            raise HTTPException(status_code=401, detail="Missing signature timestamp")

    # Compute expected signature over "ts.raw"
    to_sign = ts_str.encode("utf-8") + b"." + raw_body
    expected = "sha256=" + hmac.new(
        SIGNING_SECRET.encode("utf-8"), to_sign, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, header_sig):
        raise HTTPException(status_code=401, detail="Bad signature")


def _idempotency_key(header_key: Optional[str], obj: Dict[str, Any]) -> str:
    """
    Prefer header. Else derive from request_id + ts + direction, else full body hash.
    """
    if header_key:
        return header_key

    rid = str(obj.get("request_id") or "")
    ts = str(obj.get("ts") or "")
    direction = str(obj.get("direction") or "")
    base = f"{rid}:{ts}:{direction}".encode("utf-8", errors="ignore")
    if rid or ts or direction:
        return hashlib.sha256(base).hexdigest()[:32]

    raw = json.dumps(obj, sort_keys=True).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:32]


# --- Routes -------------------------------------------------------------------

@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"ok": True, "service": "audit-receiver", "ts": int(time.time())}


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
    raw = await request.body()

    _verify_api_key(x_api_key)
    _verify_signature(raw, x_signature, x_signature_ts)

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        event = {"_raw": raw.decode("utf-8", errors="replace")}

    idem_key = _idempotency_key(x_idempotency_key, event)
    first = IDEMP_SET.add(idem_key)
    if not first:
        log.info("Duplicate audit event dropped (idempotency): %s", idem_key)
        return {"ok": True, "duplicate": True, "idempotency_key": idem_key}

    log.info("Accepted audit event: %s", idem_key)
    return {"ok": True, "duplicate": False, "idempotency_key": idem_key}

