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

import app.telemetry.metrics as telemetry_metrics
from app.observability.metrics import (
    webhook_dlq_length_dec,
    webhook_dlq_length_inc,
    webhook_dlq_length_set,
    webhook_failed_inc,
    webhook_pending_set,
    webhook_processed_inc,
    webhook_retried_inc,
)
from app.services.config_store import get_config
from app.services.webhooks_cb import compute_backoff_ms, get_cb_registry

# Default dead-letter file path (overridable)
_DEFAULT_DLQ_PATH = "var/webhook_deadletter.jsonl"
# Test/back-compat hook: tests may monkeypatch this directly
_DLQ_PATH: Optional[str] = None

# Worker state
_lock = threading.RLock()
_q: "queue.Queue[Any]" = queue.Queue()
_worker_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_STOP = object()

# Stats (simple counters for /admin and tests)
_stats: Dict[str, Any] = {
    "queued": 0,
    "processed": 0,
    "dropped": 0,
    "last_status": "",
    "last_error": "",
    "worker_running": False,
}


def _sync_pending_queue_length() -> None:
    try:
        size = float(_q.qsize())
    except NotImplementedError:
        size = 0.0
    except Exception:
        return
    try:
        webhook_pending_set(size)
    except Exception:
        pass


def _worker_enabled() -> bool:
    try:
        cfg = get_config()
    except Exception:
        return False
    return bool(cfg.get("webhook_enable")) and bool(cfg.get("webhook_url"))


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


def _deliver(
    evt: Dict[str, Any],
) -> Tuple[str, str]:
    outcome, status, _, _ = _deliver_with_client(evt, client=None, client_conf=None)
    return outcome, status


def _deliver_with_client(
    evt: Dict[str, Any],
    *,
    client: Optional[httpx.Client],
    client_conf: Tuple[int, bool] | None,
) -> Tuple[str, str, Optional[httpx.Client], Tuple[int, bool] | None]:
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
        return "failed", "error", client, client_conf
    if not _allow_host(url, allow_host):
        return "failed", "error", client, client_conf

    reg = get_cb_registry()
    if reg.should_dlq_now(url):
        _dlq_write(evt, reason="cb_open")
        return "cb_open", "-", client, client_conf

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

    desired_conf = (timeout_ms, insecure_tls)
    if client is None or client_conf != desired_conf:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass
        client = httpx.Client(
            timeout=timeout_ms / 1000.0,
            verify=not insecure_tls,
        )
        client_conf = desired_conf

    while True:
        if attempt > 0 and reg.should_dlq_now(url):
            # If the breaker opened after the previous attempt, stop retrying immediately.
            _dlq_write(evt, reason="cb_open")
            return "cb_open", "-", client, client_conf

        attempt += 1
        t0 = time.perf_counter()
        try:
            resp = client.post(url, content=body_bytes, headers=headers)
            last_code = resp.status_code
            last_exc = None
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)
            if 200 <= resp.status_code < 300:
                reg.on_success(url)
                webhook_processed_inc()
                return "sent", _status_bucket(last_code, None), client, client_conf
            reg.on_failure(url)
        except httpx.TimeoutException:
            last_exc = "timeout"
            reg.on_failure(url)
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)
        except Exception:
            last_exc = "error"
            reg.on_failure(url)
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(time.perf_counter() - t0)

        if attempt > max_retries:
            bucket = _status_bucket(last_code, last_exc)
            _dlq_write(evt, reason=bucket)
            webhook_failed_inc()
            return "dlq", bucket, client, client_conf

        webhook_retried_inc()
        sleep_ms = compute_backoff_ms(backoff_ms, attempt - 1)
        time.sleep(sleep_ms / 1000.0)


def _worker() -> None:
    client: Optional[httpx.Client] = None
    client_conf: Tuple[int, bool] | None = None
    try:
        while True:
            if _stop_event.is_set() and _q.empty():
                _sync_pending_queue_length()
                break
            try:
                evt = _q.get(timeout=0.1)
                _sync_pending_queue_length()
            except queue.Empty:
                _sync_pending_queue_length()
                continue
            if evt is _STOP:
                _sync_pending_queue_length()
                break
            try:
                outcome, status, client, client_conf = _deliver_with_client(
                    evt, client=client, client_conf=client_conf
                )
                with _lock:
                    _stats["processed"] += 1
                    _stats["last_status"] = status
                    _stats["last_error"] = "" if outcome == "sent" else status
                # Delivery outcome metric
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome, status).inc()
                # Ensure "enqueued" shows up in flaky CI paths for failure outcomes
                if outcome != "sent":
                    telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
            except Exception as e:  # pragma: no cover
                with _lock:
                    _stats["processed"] += 1
                    _stats["last_status"] = "error"
                    _stats["last_error"] = str(e)
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels("failed", "error").inc()
                telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
            finally:
                _sync_pending_queue_length()
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass
        with _lock:
            global _worker_thread
            if _worker_thread is threading.current_thread():
                _worker_thread = None
            _stats["worker_running"] = False
        _stop_event.clear()


def _ensure_worker(*, require_enabled: bool) -> None:
    global _worker_thread
    thread_to_start: Optional[threading.Thread] = None
    with _lock:
        thread = _worker_thread
        if thread is not None and thread.is_alive():
            return
        if require_enabled and not _worker_enabled():
            return
        _stop_event.clear()
        thread_to_start = threading.Thread(
            target=_worker,
            name="webhook-worker",
            daemon=True,
        )
        _worker_thread = thread_to_start
        _stats["worker_running"] = True
    if thread_to_start is not None:
        thread_to_start.start()


def ensure_started() -> None:
    """Best-effort start of the delivery worker if webhooks are enabled."""
    try:
        _ensure_worker(require_enabled=True)
    except Exception:
        pass


def shutdown(timeout: float = 0.5) -> None:
    """Signal the worker to stop and wait briefly for exit."""
    global _worker_thread
    thread: Optional[threading.Thread]
    with _lock:
        thread = _worker_thread
        if thread is None or not thread.is_alive():
            _stats["worker_running"] = False
            return
        _stop_event.set()
        try:
            _q.put_nowait(_STOP)
        except Exception:
            pass
    try:
        thread.join(timeout=timeout)
    except Exception:
        pass
    with _lock:
        if _worker_thread is thread and not thread.is_alive():
            _worker_thread = None
        if not thread.is_alive():
            _stats["worker_running"] = False


def enqueue(evt: Dict[str, Any]) -> None:
    """Queue a decision event for delivery."""
    with _lock:
        _stats["queued"] += 1
    telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
    _ensure_worker(require_enabled=False)
    _q.put(evt)
    _sync_pending_queue_length()


def configure(*, reset: bool = False) -> None:
    """Test helper: reset counters/queue and restart worker on next enqueue."""
    global _q, _worker_thread, _stop_event

    if reset:
        shutdown()

    with _lock:
        if reset:
            _q = queue.Queue()
            _worker_thread = None
            _stop_event = threading.Event()
            for k in ("queued", "processed", "dropped"):
                _stats[k] = 0
            _stats["last_status"] = ""
            _stats["last_error"] = ""
            _stats["worker_running"] = False
            try:
                event_children = list(telemetry_metrics.WEBHOOK_EVENTS_TOTAL._metrics.keys())  # type: ignore[attr-defined]
                telemetry_metrics.WEBHOOK_EVENTS_TOTAL._metrics.clear()  # type: ignore[attr-defined]
            except AttributeError:
                event_children = []
                try:
                    child_map = telemetry_metrics.WEBHOOK_EVENTS_TOTAL._children  # type: ignore[attr-defined]
                    child_map.clear()
                except Exception:
                    pass
            else:
                for labels in event_children:
                    try:
                        telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels(*labels).inc(0)
                    except Exception:
                        pass
            try:
                delivery_children = list(telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._metrics.keys())  # type: ignore[attr-defined]
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._metrics.clear()  # type: ignore[attr-defined]
            except AttributeError:
                delivery_children = []
                try:
                    child_map = telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._children  # type: ignore[attr-defined]
                    child_map.clear()
                except Exception:
                    pass
            else:
                for labels in delivery_children:
                    try:
                        telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(*labels).inc(0)
                    except Exception:
                        pass
            try:
                get_cb_registry()._ct.clear()
            except Exception:
                pass

    _sync_pending_queue_length()

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
            _ensure_worker(require_enabled=False)

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
                        telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels("dlq_replayed", "-").inc()
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
                _sync_pending_queue_length()
            return requeued
    except Exception:
        return 0
