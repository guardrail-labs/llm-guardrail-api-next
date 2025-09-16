from __future__ import annotations

import json
import threading
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional

from app.telemetry.metrics import guardrail_webhook_events_total

_MAX_QUEUE_SIZE = 1024
_LOCK = threading.RLock()
_QUEUE: Optional[Queue[Dict[str, Any]]] = None
_WORKER: Optional[threading.Thread] = None
_STATS: Dict[str, int] = {"queued": 0, "processed": 0, "dropped": 0}
_OUTPUT_PATH: Optional[Path] = None


def configure(path: Optional[str] = None, reset: bool = False) -> None:
    """Configure optional persistence path and reset stats for tests."""

    global _OUTPUT_PATH
    with _LOCK:
        _OUTPUT_PATH = Path(path) if path else None
        if reset:
            for key in list(_STATS.keys()):
                _STATS[key] = 0


def enqueue(event: Dict[str, Any]) -> None:
    """Queue a webhook event for processing."""

    payload = dict(event)
    queue = _ensure_worker()
    try:
        queue.put_nowait(payload)
    except Full:
        guardrail_webhook_events_total.labels("dropped").inc()
        _increment_stat("dropped")
        return

    guardrail_webhook_events_total.labels("enqueued").inc()
    _increment_stat("queued")


def stats() -> Dict[str, int]:
    """Return current queue statistics."""

    with _LOCK:
        return dict(_STATS)


def _ensure_worker() -> Queue[Dict[str, Any]]:
    global _QUEUE, _WORKER
    with _LOCK:
        if _QUEUE is None:
            _QUEUE = Queue(maxsize=_MAX_QUEUE_SIZE)
        queue = _QUEUE
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(
                target=_worker_main,
                args=(queue,),
                name="webhook-worker",
                daemon=True,
            )
            _WORKER.start()
    assert queue is not None
    return queue


def _worker_main(queue: Queue[Dict[str, Any]]) -> None:
    while True:
        try:
            event = queue.get(timeout=0.2)
        except Empty:
            continue
        try:
            _process_event(event)
        finally:
            queue.task_done()


def _process_event(event: Dict[str, Any]) -> None:
    try:
        path = _current_path()
        if path is not None:
            _append_jsonl(path, event)
    except Exception:
        guardrail_webhook_events_total.labels("dropped").inc()
        _increment_stat("dropped")
        return

    guardrail_webhook_events_total.labels("processed").inc()
    _increment_stat("processed")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def _current_path() -> Optional[Path]:
    with _LOCK:
        return _OUTPUT_PATH


def _increment_stat(key: str) -> None:
    with _LOCK:
        _STATS[key] = _STATS.get(key, 0) + 1
