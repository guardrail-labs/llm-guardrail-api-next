from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi import Request

# Minimal, dependency-free normalizer used by AbuseGateMiddleware.
# Produces a compact payload per docs/VERIFIER_ADAPTERS.md (§3).


def build_normalized_payload(request: Request, body_bytes: bytes) -> Dict[str, Any]:
    prompt_text = ""
    try:
        if body_bytes:
            obj = json.loads(body_bytes.decode("utf-8"))
            # Common fields used in our handlers/tests
            prompt_text = str(obj.get("prompt") or obj.get("input") or obj.get("message") or "")
    except Exception:
        # Fall back to empty prompt
        prompt_text = ""

    # Minimal modality guess from headers/path
    ct = (request.headers.get("content-type") or "").lower()
    modalities: List[str] = []
    if "json" in ct or request.method in ("POST", "PUT", "PATCH"):
        modalities.append("text")

    # Ingress flags are not reconstructed here; the Abuse Gate operates before
    # routers attach the full debug map. Keep it empty and let adapters remain conservative.
    payload: Dict[str, Any] = {
        "prompt_text": prompt_text,
        "modalities": modalities,
        "policy_context": {
            "pii_ruleset": "default",
            "block_mode": "baseline",
            "override_mode": "clarify",
        },
        "ingress_flags": [],
        "debug": {"sources": []},
    }
    return payload
