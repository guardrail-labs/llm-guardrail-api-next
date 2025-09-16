from __future__ import annotations

import hmac
import json
import os
import queue
import threading
import time
from hashlib import sha256
from typing import Any, Dict, Optional, Tuple

import httpx

from app.services.config_store import get_config
from app.telemetry.metrics import (
    WEBHOOK_DELIVERIES_TOTAL,
    WEBHOOK_EVENTS_TOTAL,
    WEBHOOK_LATENCY_SECONDS,
)

# Dead-letter path (append JSONL on permanent failures)
_DLQ_PATH = os.getenv("WEBHOOK_DLQ_PATH", "var/webhook_deadletter.jsonl")

# Worker state
_lock = threading.RLock()
_q: "queue.SimpleQueue[Dict[str, Any]]" = queue.SimpleQueue()
_worker_started = False

# Stats (simple, not performance-critical)
_stats: Dict[str, Any] = {
    "queued": 0,
    "processed": 0,
    "dropped": 0,
    "last_status": "",
    "last_error": "",
}


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)


def _hmac_signature(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return f"sha256={mac}"


def _status_bucket(code: Optional[int], exc: Optional[str]) -> str:
    if exc:
        if exc == "timeout":
            return "timeout"
        return "error"
    if code is None:
        return "error"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "error"


def _allow_host(url: str, allow_host: str) -> bool:
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        allowed = (allow_host or "").strip()
        return (not allowed) or (host == allowed)
    except Exception:
        return False


def _dlq_write(evt: Dict[str, Any], reason: str) -> None:
    try:
        _ensure_dir(_DLQ_PATH)
        record = {"ts": int(time.time()), "reason": reason, "event": evt}
        with open(_DLQ_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except Exception:
        # Never allow DLQ persistence issues to break delivery.
        pass


def _deliver(evt: Dict[str, Any]) -> Tuple[str, str]:
    """Deliver a single event with retries.

    Returns a tuple of (outcome, status_bucket) where outcome is one of
    "sent", "failed", or "dlq".
    """

    cfg = get_config()
    url = str(cfg.get("webhook_url") or "")
    secret = str(cfg.get("webhook_secret") or "")
    timeout_ms = int(cfg.get("webhook_timeout_ms") or 2000)
    max_retries = int(cfg.get("webhook_max_retries") or 5)
    backoff_ms = int(cfg.get("webhook_backoff_ms") or 500)
    insecure_tls = bool(cfg.get("webhook_allow_insecure_tls") or False)
    allow_host = str(cfg.get("webhook_allowlist_host") or "")

    if not url:
        return "failed", "error"
    if not _allow_host(url, allow_host):
        return "failed", "error"

    body_bytes = json.dumps(evt).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Guardrail-Idempotency-Key": (
            evt.get("incident_id") or evt.get("request_id") or ""
        ),
        "X-Guardrail-Timestamp": str(int(time.time())),
    }
    if secret:
        headers["X-Guardrail-Signature"] = _hmac_signature(secret, body_bytes)

    attempt = 0
    last_code: Optional[int] = None
    last_exc: Optional[str] = None

    while True:
        attempt += 1
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=timeout_ms / 1000.0, verify=not insecure_tls) as cli:
                resp = cli.post(url, content=body_bytes, headers=headers)
            last_code = resp.status_code
            WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - started)
            if 200 <= resp.status_code < 300:
                return "sent", _status_bucket(last_code, None)
        except httpx.TimeoutException:
            last_exc = "timeout"
            WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - started)
        except Exception:
            last_exc = "error"
            WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - started)

        if attempt > max_retries:
            status = _status_bucket(last_code, last_exc)
            _dlq_write(evt, reason=status)
            return "dlq", status

        sleep_ms = backoff_ms * (2 ** (attempt - 1))
        sleep_seconds = min(sleep_ms, 10_000) / 1000.0
        time.sleep(sleep_seconds)


def _worker() -> None:
    while True:
        evt = _q.get()
        try:
            outcome, status = _deliver(evt)
            with _lock:
                _stats["processed"] += 1
                _stats["last_status"] = status
                _stats["last_error"] = "" if outcome == "sent" else status
            WEBHOOK_DELIVERIES_TOTAL.labels(outcome, status).inc()
        except Exception as exc:  # pragma: no cover
            with _lock:
                _stats["processed"] += 1
                _stats["last_status"] = "error"
                _stats["last_error"] = str(exc)
            WEBHOOK_DELIVERIES_TOTAL.labels("failed", "error").inc()


def _ensure_worker() -> None:
    global _worker_started
    with _lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_worker, name="webhook-worker", daemon=True)
        thread.start()
        _worker_started = True


def enqueue(evt: Dict[str, Any]) -> None:
    """Queue a decision event for delivery."""

    with _lock:
        _stats["queued"] += 1
    WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
    _ensure_worker()
    _q.put(evt)


def configure(*, reset: bool = False) -> None:
    """Test helper to reset in-memory counters and queue."""

    global _q, _worker_started
    with _lock:
        if reset:
            _q = queue.SimpleQueue()
            _worker_started = False
            for key in ("queued", "processed", "dropped", "last_status", "last_error"):
                value = _stats.get(key)
                _stats[key] = 0 if isinstance(value, int) else ""


def stats() -> Dict[str, Any]:
    with _lock:
        return dict(_stats)
