from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Tuple

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# Environment knob (existing tests already use these names)
_ENV_ENABLED = os.getenv("AUDIT_FORWARD_ENABLED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
_ENV_URL = os.getenv("AUDIT_FORWARD_URL") or ""
_ENV_KEY = os.getenv("AUDIT_FORWARD_API_KEY") or ""
_SAMPLE = float(os.getenv("AUDIT_SAMPLE_RATE", "1.0") or "1.0")


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _maybe_sample() -> bool:
    # Simple deterministic sampling: 1.0 = always, 0.0 = never
    try:
        return _SAMPLE >= 1.0 or _SAMPLE > 0.0
    except Exception:
        return True


def _enrich(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich without breaking existing contracts:
    - Preserve all existing keys
    - Add 'meta' sub-dict with duration_ms/route if not present
    - Add size hints if 'text' or 'prompt' exist
    """
    out = dict(event)
    meta = dict(out.get("meta") or {})
    # Avoid overwriting if caller provided
    if "duration_ms" not in meta and "duration_ms" in out:
        meta["duration_ms"] = out.pop("duration_ms")  # move under meta
    if "route" not in meta and "route" in out:
        meta["route"] = out.pop("route")

    # Size hints
    if isinstance(out.get("text"), str):
        meta.setdefault("text_size", len(out["text"]))  # type: ignore[index]
    if isinstance(out.get("prompt"), str):
        meta.setdefault("prompt_size", len(out["prompt"]))  # type: ignore[index]

    if meta:
        out["meta"] = meta
    return out


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Backward-compatible API used by routes and tests.
    Honors AUDIT_FORWARD_ENABLED / AUDIT_FORWARD_URL / AUDIT_FORWARD_API_KEY.
    """
    if not _ENV_URL or not _ENV_KEY or not _truthy(_ENV_ENABLED):
        return
    if not _maybe_sample():
        return

    enriched = _enrich(event)
    try:
        _post(_ENV_URL, _ENV_KEY, enriched)
    except Exception as exc:  # pragma: no cover
        logger.warning("audit_forwarder post failed: %s", exc)


def _post(url: str, api_key: str, payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Real HTTP POST used in prod; tests monkeypatch this symbol.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            # 'status' exists on HTTPResponse in recent Python; default for safety.
            status = getattr(resp, "status", 200)
            data = resp.read().decode("utf-8")
            return (int(status), data)
    except urllib.error.HTTPError as e:  # pragma: no cover
        return (int(e.code), e.read().decode("utf-8"))
