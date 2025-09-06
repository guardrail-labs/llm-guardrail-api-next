from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict

from app.services.audit_forwarder import emit_audit_event as _forward_emit
from app.services.policy import current_rules_version

_APP_NAME = os.getenv("APP_NAME", "llm-guardrail-api")
_ENV = os.getenv("ENV", os.getenv("APP_ENV", ""))


def emit_audit_event(event: Dict[str, Any]) -> None:
    """
    Facade for audit forwarding that normalizes/annotates payloads:
      - ensure policy_version
      - ensure request_id
      - set ts (unix seconds) if absent/None
      - add service/env tags if not provided
    """
    if not isinstance(event, dict):
        return

    if not event.get("policy_version"):
        try:
            event["policy_version"] = current_rules_version()
        except Exception:
            pass

    if not event.get("request_id"):
        event["request_id"] = str(uuid.uuid4())

    if event.get("ts") in (None, "", 0):
        try:
            event["ts"] = int(time.time())
        except Exception:
            pass

    event.setdefault("service", _APP_NAME)
    if _ENV:
        event.setdefault("env", _ENV)

    _forward_emit(event)
