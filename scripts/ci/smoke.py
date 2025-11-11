#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

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


def _prefixed_path(prefix: str, suffix: str) -> str:
    suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    base = prefix.rstrip("/")
    if not base:
        return suffix
    if base == "/":
        return suffix
    return f"{base}{suffix}"


def _attempt_openapi_discovery(
    client: httpx.Client, base: str, fallback_prefix: str
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    attempts: List[Dict[str, Any]] = []
    candidates = ["/openapi.json", _prefixed_path(fallback_prefix, "/openapi.json")]
    for suffix in dict.fromkeys(candidates):
        url = f"{base}{suffix}"
        entry: Dict[str, Any] = {"url": url}
        try:
            resp = client.get(url)
        except Exception as exc:  # pragma: no cover - diagnostics only
            entry["error"] = str(exc)
            attempts.append(entry)
            continue

        entry["status"] = resp.status_code
        if resp.status_code != 200:
            entry["error"] = f"unexpected status {resp.status_code}"
            attempts.append(entry)
            continue

        try:
            payload = resp.json()
        except Exception as exc:  # pragma: no cover - diagnostics only
            entry["error"] = f"json decode failed: {exc}"
            attempts.append(entry)
            continue

        chat_path = _discover_chat_path(payload)
        entry["chat_path"] = chat_path
        attempts.append(entry)
        if chat_path:
            return chat_path, attempts

    return None, attempts


def _report_failure(
    url: str,
    response: httpx.Response,
    target_path: str,
    discovery_attempts: List[Dict[str, Any]],
) -> None:
    detail = {
        "status_code": response.status_code,
        "body": response.text,
        "headers": dict(response.headers),
    }

    message_lines = [
        f"Smoke check failed: expected 200 from {url}, got {response.status_code}",
        f"Response: {json.dumps(detail, indent=2)}",
        f"Target path: {target_path}",
    ]
    if discovery_attempts:
        message_lines.append(
            "OpenAPI discovery attempts: "
            + json.dumps(discovery_attempts, indent=2)
        )
    print("\n".join(message_lines), file=sys.stderr)
    sys.exit(1)


def main() -> None:
    base = os.getenv("BASE", "http://127.0.0.1:8000").rstrip("/")
    prefix = _normalized_prefix(os.getenv("API_PREFIX", "/v1"))
    payload: Dict[str, Any] = {
        "model": os.getenv("SMOKE_MODEL", "demo"),
        "messages": [
            {"role": "user", "content": os.getenv("SMOKE_MESSAGE", "hello")}
        ],
    }

    headers = _build_headers()
    timeout = float(os.getenv("SMOKE_TIMEOUT", "5"))

    response: Optional[httpx.Response] = None
    discovery_attempts: List[Dict[str, Any]] = []
    target_path = _prefixed_path(prefix, "/chat/completions")

    with httpx.Client(timeout=timeout) as client:
        discovered_path, discovery_attempts = _attempt_openapi_discovery(
            client, base, prefix
        )
        if discovered_path:
            target_path = discovered_path

        url = f"{base}{target_path}"
        print(f"Smoke target URL: {url}")

        response = client.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            _report_failure(url, response, target_path, discovery_attempts)

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

        missing_404 = client.get(f"{base}/definitely-not-a-route")
        if not missing_404.headers.get("X-Guardrail-Mode"):
            detail = {
                "status_code": missing_404.status_code,
                "headers": dict(missing_404.headers),
                "body": missing_404.text,
            }
            print(
                "Smoke check failed: 404 response missing X-Guardrail-Mode",
                json.dumps(detail, indent=2),
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
