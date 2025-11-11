#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import httpx


def _normalized_prefix(prefix: str) -> str:
    if not prefix:
        return "/v1"
    if not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return prefix.rstrip("/") or "/"


def _build_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {
        "content-type": "application/json",
        "x-api-key": os.getenv("SMOKE_API_KEY", "smoke-token"),
    }
    tenant = os.getenv("SMOKE_TENANT")
    bot = os.getenv("SMOKE_BOT")
    if tenant:
        headers["x-guardrail-tenant"] = tenant
    if bot:
        headers["x-guardrail-bot"] = bot
    request_id = os.getenv("SMOKE_REQUEST_ID")
    if request_id:
        headers["x-request-id"] = request_id
    return headers


def main() -> None:
    base = os.getenv("BASE", "http://127.0.0.1:8000").rstrip("/")
    prefix = _normalized_prefix(os.getenv("API_PREFIX", "/v1"))
    url = f"{base}{prefix}/chat/completions"

    payload: Dict[str, Any] = {
        "messages": [{"role": "user", "content": os.getenv("SMOKE_MESSAGE", "hello")}],
    }

    headers = _build_headers()
    timeout = float(os.getenv("SMOKE_TIMEOUT", "5"))

    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload, headers=headers)

    if response.status_code != 200:
        detail = {
            "status_code": response.status_code,
            "body": response.text,
            "headers": dict(response.headers),
        }
        print(
            f"Smoke check failed: expected 200 from {url}, got {response.status_code}\n"
            f"Response: {json.dumps(detail, indent=2)}",
            file=sys.stderr,
        )
        sys.exit(1)

    missing = [
        header
        for header in ("X-Guardrail-Decision", "X-Guardrail-Mode")
        if not response.headers.get(header)
    ]
    if missing:
        print(
            f"Smoke check failed: missing required headers {missing} from {url}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        "Smoke OK",
        json.dumps(
            {
                "url": url,
                "decision": response.headers.get("X-Guardrail-Decision"),
                "mode": response.headers.get("X-Guardrail-Mode"),
                "request_id": response.headers.get("X-Request-ID"),
            }
        ),
    )


if __name__ == "__main__":
    main()
