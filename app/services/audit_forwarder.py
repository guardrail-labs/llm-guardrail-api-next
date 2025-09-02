from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _maybe_sample(sample: float) -> bool:
    # Simple deterministic sampling: 1.0 = always, 0.0 = never
    try:
        return sample >= 1.0 or sample > 0.0
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
        meta["duration_ms"] = out.pop("duration_ms")
    if "route" not in meta and "route" in out:
        meta["route"] = out.pop("route")

    # Size hints
    txt = ""
    if isinstance(out.get("text"), str):
        txt = out["text"]  # type: ignore[index]
        meta.setdefault("text_size", len(txt))
    if isinstance(out.get("prompt"), str):
        pr = out["prompt"]  # type: ignore[index]
        meta.setdefault("prompt_size", len(pr))

    if meta:
        out["meta"] = meta
    return out


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Backward-compatible API used by routes and tests.
    Honors AUDIT_FORWARD_ENABLED / AUDIT_FORWARD_URL / AUDIT_FORWARD_API_KEY.
    """
    if not _truthy(os.getenv("AUDIT_FORWARD_ENABLED", "false")):
        return
    url = os.getenv("AUDIT_FORWARD_URL") or ""
    key = os.getenv("AUDIT_FORWARD_API_KEY") or ""
    if not url or not key:
        return

    sample = float(os.getenv("AUDIT_SAMPLE_RATE", "1.0") or "1.0")
    if not _maybe_sample(sample):
        return

    enriched = _enrich(event)
    try:
        _post(url, key, enriched)
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
            status = getattr(resp, "status", 200)  # type: ignore[attr-defined]
            data = resp.read().decode("utf-8")
            return (int(status), data)
    except urllib.error.HTTPError as e:  # pragma: no cover
        return (int(e.code), e.read().decode("utf-8"))


# Backward compatibility with older imports
emit_event = emit_audit_event

