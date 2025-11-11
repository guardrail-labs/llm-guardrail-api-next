#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

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


def _discover_chat_path(payload: Dict[str, Any]) -> Optional[str]:
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return None
    for path in paths:
        if isinstance(path, str) and path.endswith("/chat/completions"):
            return path
    return None


def _report_failure(
    client: httpx.Client,
    base: str,
    prefix: str,
    url: str,
    response: httpx.Response,
) -> None:
    detail = {
        "status_code": response.status_code,
        "body": response.text,
        "headers": dict(response.headers),
    }
    openapi_url = f"{base}{prefix}/openapi.json"
    discovered: Optional[str] = None
    fallback_error: Optional[str] = None
    try:
        schema_resp = client.get(openapi_url)
        schema_resp.raise_for_status()
        discovered = _discover_chat_path(schema_resp.json())
    except Exception as exc:  # pragma: no cover - diagnostics only
        fallback_error = str(exc)

    message_lines = [
        f"Smoke check failed: expected 200 from {url}, got {response.status_code}",
        f"Response: {json.dumps(detail, indent=2)}",
    ]
    if discovered:
        message_lines.append(
            f"Discovered chat endpoint at '{discovered}' via {openapi_url}. "
            "Set API_PREFIX accordingly."
        )
    elif fallback_error:
        message_lines.append(
            f"Fallback probe {openapi_url} failed: {fallback_error}"
        )
    print("\n".join(message_lines), file=sys.stderr)
    sys.exit(1)


def main() -> None:
    base = os.getenv("BASE", "http://127.0.0.1:8000").rstrip("/")
    prefix = _normalized_prefix(os.getenv("API_PREFIX", "/v1"))
    url = f"{base}{prefix}/chat/completions"
    print(f"Smoke target URL: {url}")

    payload: Dict[str, Any] = {
        "model": os.getenv("SMOKE_MODEL", "demo"),
        "messages": [
            {"role": "user", "content": os.getenv("SMOKE_MESSAGE", "hello")}
        ],
    }

    headers = _build_headers()
    timeout = float(os.getenv("SMOKE_TIMEOUT", "5"))

    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            _report_failure(client, base, prefix, url, response)

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
