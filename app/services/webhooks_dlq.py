from __future__ import annotations

import json
import os
import time
from contextlib import nullcontext
from typing import Any, Dict, Iterator, Optional

from app.observability.metrics import webhook_dlq_length_inc, webhook_dlq_length_set
from app.services import webhooks


def _dlq_path() -> str:
    path_fn = getattr(webhooks, "_dlq_path", None)
    if callable(path_fn):
        return str(path_fn())
    env_path = os.getenv("WEBHOOK_DLQ_PATH")
    if env_path:
        return env_path
    default_path = getattr(webhooks, "_DEFAULT_DLQ_PATH", "var/webhook_deadletter.jsonl")
    return str(default_path)


def _lock_ctx():
    lock = getattr(webhooks, "_lock", None)
    return lock if lock is not None else nullcontext()


def _ensure_dir(path: str) -> None:
    ensure_dir = getattr(webhooks, "_ensure_dir", None)
    if callable(ensure_dir):
        ensure_dir(path)
        return
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)


def _iter_records(path: str) -> Iterator[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if isinstance(rec, dict):
                    yield rec
    except FileNotFoundError:
        return
    except Exception:
        return


def _ts_to_ms(raw: Any) -> Optional[int]:
    if isinstance(raw, (int, float)):
        value = int(raw)
    elif isinstance(raw, str):
        try:
            value = int(float(raw))
        except Exception:
            return None
    else:
        return None

    if value <= 0:
        return None
    if value < 1_000_000_000_000:  # assume seconds
        return value * 1000
    return value


def _record_error(rec: Dict[str, Any]) -> Optional[str]:
    reason = rec.get("reason")
    if isinstance(reason, str) and reason:
        return reason
    err = rec.get("error")
    if isinstance(err, str) and err:
        return err
    evt = rec.get("event")
    if isinstance(evt, dict):
        payload_err = evt.get("error") or evt.get("reason")
        if isinstance(payload_err, str) and payload_err:
            return payload_err
    return None


def push(ts_ms: int, payload: Dict[str, Any], error: str) -> None:
    """Testing helper to append a DLQ record."""

    path = _dlq_path()
    ts_value = int(ts_ms)
    ts_sec = ts_value // 1000 if ts_value >= 1000 else ts_value
    record = {
        "ts": ts_sec or int(time.time()),
        "ts_ms": ts_value if ts_value > 0 else int(time.time() * 1000),
        "reason": error,
        "event": payload,
    }
    with _lock_ctx():
        _ensure_dir(path)
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            return
        try:
            webhook_dlq_length_inc(1)
        except Exception:
            pass


def stats() -> Dict[str, Optional[int | str]]:
    path = _dlq_path()
    size = 0
    oldest_ms: Optional[int] = None
    newest_ms: Optional[int] = None
    last_error: Optional[str] = None

    with _lock_ctx():
        for rec in _iter_records(path):
            size += 1
            ts_ms = rec.get("ts_ms")
            ts_value = _ts_to_ms(ts_ms) if ts_ms is not None else _ts_to_ms(rec.get("ts"))
            if ts_value is not None:
                if oldest_ms is None or ts_value < oldest_ms:
                    oldest_ms = ts_value
                if newest_ms is None or ts_value > newest_ms:
                    newest_ms = ts_value
            err = _record_error(rec)
            if err:
                last_error = err

    if size == 0:
        return {
            "size": 0,
            "oldest_ts_ms": None,
            "newest_ts_ms": None,
            "last_error": None,
        }
    return {
        "size": size,
        "oldest_ts_ms": oldest_ms,
        "newest_ts_ms": newest_ms,
        "last_error": last_error,
    }


def retry_all() -> int:
    total = 0
    while True:
        try:
            requeued = webhooks.requeue_from_dlq(1000)
        except Exception:
            break
        if requeued <= 0:
            break
        total += requeued
        if requeued < 1000:
            break
    return total


def purge_all() -> int:
    path = _dlq_path()
    with _lock_ctx():
        count = sum(1 for _ in _iter_records(path))
        if count == 0:
            return 0
        try:
            os.remove(path)
        except FileNotFoundError:
            count = 0
        except Exception:
            return 0
        try:
            webhook_dlq_length_set(0)
        except Exception:
            pass
        return count
