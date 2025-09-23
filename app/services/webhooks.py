from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import random
import threading
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

import httpx

import app.telemetry.metrics as telemetry_metrics
from app.observability.metrics import (
    webhook_abort_total,
    webhook_dlq_depth,
    webhook_dlq_length_dec,
    webhook_dlq_length_get,
    webhook_dlq_length_inc,
    webhook_dlq_length_set,
    webhook_failed_inc,
    webhook_pending_set,
    webhook_processed_inc,
    webhook_retried_inc,
    webhook_retry_total,
)
from app.services.config_store import get_config
from app.services.webhooks_cb import get_cb_registry


_log = logging.getLogger(__name__)


def _best_effort(msg: str, fn: Callable[[], Any]) -> None:
    try:
        fn()
    except Exception as exc:  # pragma: no cover
        _log.debug("%s: %s", msg, exc)


def _set_dlq_depth(value: Optional[int | float] = None) -> None:
    def update() -> None:
        target = value if value is not None else webhook_dlq_length_get()
        webhook_dlq_depth.set(max(0, int(target)))

    _best_effort("set webhook DLQ depth", update)


def _get_cfg_dict() -> Dict[str, Any]:
    """
    Safely fetch in-memory webhook config if available; otherwise empty.
    Avoids circular imports by using globals().
    """

    try:
        if "get_config" in globals() and callable(globals()["get_config"]):
            cfg = globals()["get_config"]()
            if isinstance(cfg, dict):
                return cfg
            if isinstance(cfg, Mapping):
                return dict(cfg)
    except Exception as exc:  # pragma: no cover
        _log.debug("load webhook config dict failed: %s", exc)
    return {}


def _cfg_or_env_int(
    cfg: Dict[str, Any],
    cfg_key: str,
    env_key: str,
    default: int,
) -> int:
    v = cfg.get(cfg_key)
    if v is None:
        v = os.getenv(env_key)
    try:
        return int(v) if v is not None else default
    except Exception as exc:  # pragma: no cover
        _log.debug(
            "invalid webhook config int for %s/%s: %s",
            cfg_key,
            env_key,
            exc,
        )
        return default


def _backoff_params() -> tuple[int, int, int, int]:
    """
    Returns (base_ms, max_ms, max_attempts, horizon_ms).
    Prefers in-memory config keys set via set_config(...), with env fallback.
    """

    cfg = _get_cfg_dict()

    base_ms = _cfg_or_env_int(cfg, "webhook_backoff_ms", "WEBHOOK_BACKOFF_BASE_MS", 250)
    base_ms = max(1, base_ms)

    max_ms_raw = _cfg_or_env_int(
        cfg,
        "webhook_backoff_max_ms",
        "WEBHOOK_BACKOFF_MAX_MS",
        900_000,
    )
    max_ms = max(base_ms, max_ms_raw)

    env_attempts_raw = os.getenv("WEBHOOK_MAX_ATTEMPTS")
    try:
        env_attempts = int(env_attempts_raw) if env_attempts_raw is not None else 12
    except Exception:
        env_attempts = 12
    env_attempts = max(1, env_attempts)

    cfg_retries = cfg.get("webhook_max_retries")
    cfg_attempts: Optional[int]
    if cfg_retries is not None:
        try:
            cfg_attempts = max(1, int(cfg_retries) + 1)
        except Exception:
            cfg_attempts = None
    else:
        cfg_attempts = None

    max_attempts = (
        env_attempts if cfg_attempts is None else min(env_attempts, cfg_attempts)
    )

    # IMPORTANT: keep default horizon constant (15m) unless explicitly overridden.
    # Do NOT couple to per-attempt max backoff; callers lowering max_ms should not
    # implicitly shrink total retry budget.
    horizon_ms_raw = _cfg_or_env_int(
        cfg,
        "webhook_max_horizon_ms",
        "WEBHOOK_MAX_HORIZON_MS",
        900_000,
    )
    horizon_ms = max(0, horizon_ms_raw)

    return base_ms, max_ms, max_attempts, horizon_ms


# Type signature for a one-shot attempt. Return (ok, status_code, err_kind)
# err_kind in {"network","timeout","5xx","4xx", "cb_open", None}
SendOnce = Callable[[], Tuple[bool, int | None, str | None]]


def _sleep_ms(ms: int) -> None:
    time.sleep(ms / 1000.0)


def _decorrelated_jitter_sleep_ms(
    prev_sleep_ms: int,
    base_ms: int,
    max_ms: int,
) -> int:
    """AWS-style decorrelated jitter backoff."""

    low = base_ms
    high = max(base_ms, prev_sleep_ms * 3)
    return min(max_ms, int(random.uniform(low, high)))


def _should_retry(
    status_code: int | None,
    err_kind: str | None,
) -> Tuple[bool, str | None]:
    if err_kind == "cb_open":
        return False, "cb_open"
    if err_kind in ("network", "timeout"):
        return True, err_kind
    if status_code is None:
        return True, "network"
    if 500 <= status_code <= 599:
        return True, "5xx"
    if 400 <= status_code <= 499:
        return False, "4xx"
    return False, None


def _deliver_with_backoff(
    send_once: SendOnce,
    *,
    state: Optional[Dict[str, Any]] = None,
) -> bool:
    """Attempt delivery using decorrelated jitter backoff."""

    base_ms, max_ms, max_attempts, max_horizon_ms = _backoff_params()

    attempts = 0
    start = time.monotonic()
    base_ms = max(1, int(base_ms))
    max_ms = max(base_ms, int(max_ms))
    max_attempts = max(1, int(max_attempts))
    max_horizon_ms = max(0, int(max_horizon_ms))
    sleep_ms = base_ms

    while True:
        attempts += 1
        ok, status, err = send_once()
        if state is not None:
            state["last_status"] = status
            state["last_error"] = err
            state["attempts"] = attempts
        if ok:
            if state is not None:
                state["abort_reason"] = None
            return True

        retry, reason = _should_retry(status, err)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not retry:
            abort_reason = reason or "4xx"
            if state is not None:
                state["abort_reason"] = abort_reason
            webhook_abort_total.labels(abort_reason).inc()
            return False

        if attempts >= max_attempts:
            if state is not None:
                state["abort_reason"] = "attempts"
            webhook_abort_total.labels("attempts").inc()
            return False

        if max_horizon_ms and elapsed_ms >= max_horizon_ms:
            if state is not None:
                state["abort_reason"] = "horizon"
            webhook_abort_total.labels("horizon").inc()
            return False

        webhook_retry_total.labels(reason or "network").inc()
        webhook_retried_inc()

        next_sleep = _decorrelated_jitter_sleep_ms(sleep_ms, base_ms, max_ms)
        _sleep_ms(next_sleep)
        sleep_ms = next_sleep


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
    except Exception as exc:  # pragma: no cover
        _log.debug("compute webhook queue size failed: %s", exc)
        return
    _best_effort("set webhook pending gauge", lambda: webhook_pending_set(size))


def _worker_enabled() -> bool:
    try:
        cfg = get_config()
    except Exception as exc:  # pragma: no cover
        _log.debug("read webhook worker config failed: %s", exc)
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
    except Exception as exc:  # pragma: no cover
        _log.debug("allow host check failed: %s", exc)
        return False


def _dlq_write(evt: Dict[str, Any], reason: str) -> None:
    """
    Append a failed event to DLQ. Synchronized with the same lock used by replay
    to avoid dropping lines during an os.replace rewrite.
    """

    def append() -> None:
        path = _dlq_path()
        rec = {"ts": int(time.time()), "reason": reason, "event": evt}
        with _lock:
            _ensure_dir(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            webhook_dlq_length_inc(1)
            _set_dlq_depth()

    _best_effort("append webhook DLQ", append)


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
    insecure_tls = bool(cfg.get("webhook_allow_insecure_tls") or False)
    allow_host = str(cfg.get("webhook_allowlist_host") or "")

    if not url:
        return "failed", "error", client, client_conf
    if not _allow_host(url, allow_host):
        return "failed", "error", client, client_conf

    reg = get_cb_registry()
    if reg.should_dlq_now(url):
        webhook_abort_total.labels("cb_open").inc()
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

    last_code: Optional[int] = None
    last_exc: Optional[str] = None

    desired_conf = (timeout_ms, insecure_tls)
    if client is None or client_conf != desired_conf:
        if client is not None:
            _best_effort("close webhook client", client.close)
        client = httpx.Client(
            timeout=timeout_ms / 1000.0,
            verify=not insecure_tls,
        )
        client_conf = desired_conf

    abort_state: Dict[str, Any] = {}

    def _send_once() -> Tuple[bool, int | None, str | None]:
        nonlocal last_code, last_exc

        if reg.should_dlq_now(url):
            last_code = None
            last_exc = "cb_open"
            return False, None, "cb_open"

        t0 = time.perf_counter()
        try:
            resp = client.post(url, content=body_bytes, headers=headers)
            last_code = resp.status_code
            last_exc = None
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(
                time.perf_counter() - t0
            )
            if 200 <= resp.status_code < 300:
                reg.on_success(url)
                webhook_processed_inc()
                return True, resp.status_code, None
            reg.on_failure(url)
            err_kind: str | None = None
        except httpx.TimeoutException:
            last_code = None
            last_exc = "timeout"
            reg.on_failure(url)
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(
                time.perf_counter() - t0
            )
            err_kind = "timeout"
        except Exception:
            last_code = None
            last_exc = "error"
            reg.on_failure(url)
            telemetry_metrics.WEBHOOK_LATENCY_SECONDS.observe(
                time.perf_counter() - t0
            )
            err_kind = "network"
        else:
            err_kind = None

        if reg.should_dlq_now(url):
            abort_state["abort_reason"] = "cb_open"
            return False, last_code, "cb_open"

        return False, last_code, err_kind

    ok = _deliver_with_backoff(
        _send_once,
        state=abort_state,
    )
    if ok:
        return "sent", _status_bucket(last_code, None), client, client_conf

    abort_reason = abort_state.get("abort_reason")
    if abort_reason == "cb_open" or reg.should_dlq_now(url):
        _dlq_write(evt, reason="cb_open")
        return "cb_open", "-", client, client_conf

    bucket = _status_bucket(last_code, last_exc)
    _dlq_write(evt, reason=bucket)
    webhook_failed_inc()
    return "dlq", bucket, client, client_conf


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
                    evt,
                    client=client,
                    client_conf=client_conf,
                )
                with _lock:
                    _stats["processed"] += 1
                    _stats["last_status"] = status
                    _stats["last_error"] = "" if outcome == "sent" else status
                # Delivery outcome metric
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(
                    outcome,
                    status,
                ).inc()
                # Ensure "enqueued" shows up in flaky CI paths for failure outcomes
                if outcome != "sent":
                    telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels(
                        "enqueued"
                    ).inc()
            except Exception as e:  # pragma: no cover
                with _lock:
                    _stats["processed"] += 1
                    _stats["last_status"] = "error"
                    _stats["last_error"] = str(e)
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(
                    "failed",
                    "error",
                ).inc()
                telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels("enqueued").inc()
            finally:
                _sync_pending_queue_length()
    finally:
        if client is not None:
            _best_effort("close webhook client on shutdown", client.close)
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
    _best_effort(
        "ensure webhook worker",
        lambda: _ensure_worker(require_enabled=True),
    )


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
        _best_effort(
            "signal webhook worker stop",
            lambda: _q.put_nowait(_STOP),
        )
    _best_effort("join webhook worker", lambda: thread.join(timeout=timeout))
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
                event_children = list(
                    telemetry_metrics.WEBHOOK_EVENTS_TOTAL._metrics.keys()  # type: ignore[attr-defined]  # noqa: SLF001
                )
                telemetry_metrics.WEBHOOK_EVENTS_TOTAL._metrics.clear()  # type: ignore[attr-defined]  # noqa: SLF001
            except AttributeError:
                event_children = []

                def clear_event_children() -> None:
                    telemetry_metrics.WEBHOOK_EVENTS_TOTAL._children.clear()  # type: ignore[attr-defined]  # noqa: SLF001

                _best_effort(
                    "clear webhook event metric children",
                    clear_event_children,
                )
            else:
                for labels in event_children:
                    # mypy: make label tuple type explicit
                    def _prime_event_child(
                        ls: tuple[str, ...] = tuple(labels),
                    ) -> None:
                        telemetry_metrics.WEBHOOK_EVENTS_TOTAL.labels(*ls).inc(0)

                    _best_effort(
                        "prime webhook event metric child",
                        _prime_event_child,
                    )
            try:
                delivery_children = list(
                    telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._metrics.keys()  # type: ignore[attr-defined]  # noqa: SLF001
                )
                telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._metrics.clear()  # type: ignore[attr-defined]  # noqa: SLF001
            except AttributeError:
                delivery_children = []

                def clear_delivery_children() -> None:
                    telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL._children.clear()  # type: ignore[attr-defined]  # noqa: SLF001

                _best_effort(
                    "clear webhook delivery metric children",
                    clear_delivery_children,
                )
            else:
                for labels in delivery_children:
                    # mypy: make label tuple type explicit
                    def _prime_delivery_child(
                        ls: tuple[str, ...] = tuple(labels),
                    ) -> None:
                        telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(*ls).inc(0)

                    _best_effort(
                        "prime webhook delivery metric child",
                        _prime_delivery_child,
                    )
            _best_effort(
                "clear webhook circuit breaker cache",
                lambda: get_cb_registry()._ct.clear(),
            )

    _sync_pending_queue_length()

    # Always sync the DLQ gauge to the current backlog so restarts immediately
    # reflect reality. Previously this only ran for reset=True which left the
    # gauge stale on cold starts.
    def seed_gauges() -> None:
        current_count = dlq_count()
        webhook_dlq_length_set(current_count)
        _set_dlq_depth(current_count)

    _best_effort("seed webhook DLQ gauges", seed_gauges)


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
                _set_dlq_depth(0)
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
                        telemetry_metrics.WEBHOOK_DELIVERIES_TOTAL.labels(
                            "dlq_replayed",
                            "-",
                        ).inc()
                    else:
                        survivors.append(line)
                except Exception:
                    survivors.append(line)

            tmp_path = f"{path}.tmp"
            _ensure_dir(path)
            with open(tmp_path, "w", encoding="utf-8") as out:
                out.writelines(survivors)
            os.replace(tmp_path, path)

            _set_dlq_depth(len(survivors))
            if requeued:
                webhook_dlq_length_dec(requeued)
                _sync_pending_queue_length()
            return requeued
    except Exception:
        return 0
