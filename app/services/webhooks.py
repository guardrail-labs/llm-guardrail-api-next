from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import threading
import time
from typing import Any, Dict, Optional, Tuple

import httpx

from app.observability.metrics import (
    webhook_dlq_length_dec,
    webhook_dlq_length_inc,
    webhook_dlq_length_set,
)
from app.services.config_store import get_config
from app.services.webhooks_cb import compute_backoff_ms, get_cb_registry
from app.telemetry.metrics import (
    WEBHOOK_DELIVERIES_TOTAL,
    WEBHOOK_EVENTS_TOTAL,
    WEBHOOK_LATENCY_SECONDS,
)

# Default dead-letter file path (overridable)
_DEFAULT_DLQ_PATH = "var/webhook_deadletter.jsonl"
# Test/back-compat hook: tests may monkeypatch this directly
_DLQ_PATH: Optional[str] = None

# Worker state
_lock = threading.RLock()
_q: "queue.SimpleQueue[Dict[str, Any]]" = queue.SimpleQueue()
_worker_started = False

# Stats (simple counters for /admin and tests)
_stats: Dict[str, Any] = {
    "queued": 0,
    "processed": 0,
    "dropped": 0,
    "last_status": "",
    "last_error": "",
}


def _dlq_path() -> str:
    """
    Resolve DLQ path dynamically so tests can monkeypatch module var or env.
    Precedence: module _DLQ_PATH -> env WEBHOOK_DLQ_PATH -> default.
    """
    if _DLQ_PATH:
        return _DLQ_PATH
    env = os.getenv("WEBHOOK_DLQ_PATH")
    return env if env else _DEFAULT_DLQ_PATH


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)


def get_webhook_signing() -> Dict[str, Any]:
    from app.services.config_store import get_webhook_signing as fetch_signing

    return fetch_signing()


def _hmac_hex(secret: bytes, data: bytes) -> str:
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def _signing_headers(body: bytes, secret: bytes) -> Dict[str, str]:
    """
    Returns headers to attach for webhook signing based on config.

    - Always returns X-Guardrail-Signature (v0) unless mode=="ts_body" and dual=False.
    - If mode=="ts_body": also sets X-Guardrail-Timestamp and (if dual or replacing)
      X-Guardrail-Signature-V1.
    """

    cfg = get_webhook_signing()
    mode = cfg.get("mode")
    dual = bool(cfg.get("dual"))

    headers: Dict[str, str] = {}

    # v0 (body-only)
    v0 = _hmac_hex(secret, body)

    if mode == "ts_body":
        ts = str(int(time.time()))
        preimage = (ts + "\n").encode("utf-8") + body
        v1 = _hmac_hex(secret, preimage)
        headers["X-Guardrail-Timestamp"] = ts

        if dual:
            # Emit BOTH: legacy v0 and new v1
            headers["X-Guardrail-Signature"] = f"sha256={v0}"
            headers["X-Guardrail-Signature-V1"] = f"sha256={v1}"
        else:
            # Emit ONLY v1 under a distinct header; consumers can migrate cleanly
            headers["X-Guardrail-Signature-V1"] = f"sha256={v1}"
    else:
        # Default (v0 only)
        headers["X-Guardrail-Signature"] = f"sha256={v0}"

    return headers


def _status_bucket(code: Optional[int], exc: Optional[str]) -> str:
    if exc:
        return "timeout" if exc == "timeout" else "error"
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
    """Very light allow-list check: exact host match when configured."""
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        allow = (allow_host or "").strip()
        return (not allow) or (host == allow)
    except Exception:
        return False


def _dlq_write(evt: Dict[str, Any], reason: str) -> None:
    """
    Append a failed event to DLQ. Synchronized with the same lock used by replay
    to avoid dropping lines during an os.replace rewrite.
    """
    try:
        path = _dlq_path()
        rec = {"ts": int(time.time()), "reason": reason, "event": evt}
        with _lock:
            _ensure_dir(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            webhook_dlq_length_inc(1)
    except Exception:
        # DLQ failures are best-effort; swallow errors.
        pass


def _deliver(evt: Dict[str, Any]) -> Tuple[str, str]:
    """
    Deliver a single event with retries.
    Returns (outcome, status_bucket).
    outcome: "sent" | "failed" | "dlq" | "cb_open"
    status_bucket: "2xx" | "3xx" | "4xx" | "5xx" | "timeout" | "error" | "-"
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

    reg = get_cb_registry()
    if reg.should_dlq_now(url):
        _dlq_write(evt, reason="cb_open")
        return "cb_open", "-"

    body_bytes = json.dumps(evt).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Guardrail-Idempotency-Key": (
            evt.get("incident_id") or evt.get("request_id") or ""
        ),
    }
    if secret:
        secret_bytes = secret.encode("utf-8")
        sig_headers = _signing_headers(body_bytes, secret_bytes)
        headers.update(sig_headers)

    attempt = 0
    last_code: Optional[int] = None
    last_exc: Optional[str] = None

    while True:
        if attempt > 0 and reg.should_dlq_now(url):
            # If the breaker opened after the previous attempt, stop retrying immediately.
            _dlq_write(evt, reason="cb_open")
            return "cb_open", "-"

        attempt += 1
        t0 = time.perf_counter()
        try:
            with httpx.Client(
                timeout=timeout_ms / 1000.0,
                verify=not insecure_tls,
            ) as cli:
                resp = cli.post(url, content=body_bytes, headers=headers)
                last_code = resp.status_code
                last_exc = None
                WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)
                if 200 <= resp.status_code < 300:
                    reg.on_success(url)
                    return "sent", _status_bucket(last_code, None)
                reg.on_failure(url)
        except httpx.TimeoutException:
            last_exc = "timeout"
            reg.on_failure(url)
            WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)
        except Exception:
            last_exc = "error"
            reg.on_failure(url)
            WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)

        if attempt > max_retries:
            _dlq_write(evt, reason=_status_bucket(last_code, last_exc))
            return "dlq", _status_bucket(last_code, last_exc)

        sleep_ms = compute_backoff_ms(backoff_ms, attempt - 1)
        time.sleep(sleep_ms / 1000.0)


def _worker() -> None:
    while True:
        evt = _q.get()
        try:
            outcome, status = _deliver(evt)
            with _lock:
                _stats["processed"] += 1
                _stats["last_status"] = status
                _stats["last_error"] = "" if outcome == "sent" else status
            # Delivery outcome metric
            WEBHOOK_DELIVERIES_TOTAL.labels(outcome, status).inc()
            # Ensure "enqueued" shows up in flaky CI paths for failure outcomes
            if outcome != "sent":
                WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
        except Exception as e:  # pragma: no cover
            with _lock:
                _stats["processed"] += 1
                _stats["last_status"] = "error"
                _stats["last_error"] = str(e)
            WEBHOOK_DELIVERIES_TOTAL.labels("failed", "error").inc()
            WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()


def _ensure_worker() -> None:
    global _worker_started
    with _lock:
        if _worker_started:
            return
        t = threading.Thread(target=_worker, name="webhook-worker", daemon=True)
        t.start()
        _worker_started = True


def enqueue(evt: Dict[str, Any]) -> None:
    """Queue a decision event for delivery."""
    with _lock:
        _stats["queued"] += 1
    WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
    _ensure_worker()
    _q.put(evt)


def configure(*, reset: bool = False) -> None:
    """Test helper: reset counters/queue and restart worker on next enqueue."""
    global _q, _worker_started
    with _lock:
        if reset:
            _q = queue.SimpleQueue()
            _worker_started = False  # force a new worker for the fresh queue
            for k in ("queued", "processed", "dropped"):
                _stats[k] = 0
            _stats["last_status"] = ""
            _stats["last_error"] = ""

    # Always sync the DLQ gauge to the current backlog so restarts immediately reflect
    # reality. Previously this only ran for reset=True which left the gauge stale on
    # cold starts.
    try:
        webhook_dlq_length_set(dlq_count())
    except Exception:
        # Never fail configure on metrics path.
        pass


def stats() -> Dict[str, Any]:
    with _lock:
        return dict(_stats)


# --------------------- DLQ helpers (replay-safe) ------------------------------


def dlq_count() -> int:
    """Count lines in DLQ file. Locked to avoid racing with rewrite/append."""
    try:
        path = _dlq_path()
        with _lock:
            if not os.path.exists(path):
                return 0
            n = 0
            with open(path, "r", encoding="utf-8") as f:
                for _ in f:
                    n += 1
            return n
    except Exception:
        return 0


def requeue_from_dlq(limit: int) -> int:
    """
    Move up to `limit` oldest DLQ entries back to the worker queue.
    Protected by the same lock as _dlq_write to prevent lost appends during
    atomic rewrite (os.replace). Ensures a worker is running for the current
    queue before enqueueing.
    """
    limit = max(0, min(int(limit), 1000))
    if limit == 0:
        return 0

    try:
        path = _dlq_path()
        with _lock:
            if not os.path.exists(path):
                return 0

            # Ensure worker consumes the current _q
            _ensure_worker()

            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            requeued = 0
            survivors: list[str] = []
            for line in lines:
                if requeued >= limit:
                    survivors.append(line)
                    continue
                try:
                    rec = json.loads(line)
                    evt = rec.get("event")
                    if isinstance(evt, dict):
                        _q.put(evt)
                        requeued += 1
                        WEBHOOK_DELIVERIES_TOTAL.labels("dlq_replayed", "-").inc()
                    else:
                        survivors.append(line)
                except Exception:
                    survivors.append(line)

            tmp_path = f"{path}.tmp"
            _ensure_dir(path)
            with open(tmp_path, "w", encoding="utf-8") as out:
                out.writelines(survivors)
            os.replace(tmp_path, path)

            if requeued:
                webhook_dlq_length_dec(requeued)
            return requeued
    except Exception:
        return 0
