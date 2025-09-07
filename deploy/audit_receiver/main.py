from __future__ import annotations
import os, hmac, hashlib, json, time
from typing import Any, Dict
from fastapi import FastAPI, Request, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Guardrail Audit Receiver", version="0.1")

INGEST = Counter(
    "audit_receiver_ingest_total",
    "Audit ingests by result",
    ["result"],
)
LAT = Histogram(
    "audit_receiver_ingest_seconds",
    "Ingest latency seconds",
)

SECRET = os.environ.get("AUDIT_SIGNING_SECRET", "").encode()

@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "ts": int(time.time())}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/ingest")
async def ingest(req: Request):
    started = time.perf_counter()
    body = await req.body()
    sig = req.headers.get("X-Audit-Signature", "")
    try:
        if SECRET:
            mac = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, sig or ""):
                INGEST.labels("bad_sig").inc()
                LAT.observe(time.perf_counter() - started)
                return {"ok": False, "error": "bad_sig"}
        _ = json.loads(body.decode("utf-8", "ignore"))
        INGEST.labels("ok").inc()
        LAT.observe(time.perf_counter() - started)
        return {"ok": True}
    except Exception:
        INGEST.labels("error").inc()
        LAT.observe(time.perf_counter() - started)
        return {"ok": False}
