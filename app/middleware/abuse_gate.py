from __future__ import annotations

import hashlib
import os
from typing import Optional

from fastapi import Request as FastAPIRequest
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.services.abuse.engine import (
    AbuseConfig,
    AbuseEngine,
    Decision,
    Subject,
    decision_headers,
    generate_incident_id,
)
from app.services.verifier.adapters.base import resolve_adapter_from_env
from app.services.verifier.payload import build_normalized_payload


def _enabled(env: str, default: bool = True) -> bool:
    raw = os.getenv(env)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _header(scope: Scope, name: str) -> str:
    target = name.lower().encode("latin-1")
    for k, v in scope.get("headers") or []:
        if k.lower() == target:
            return v.decode("latin-1")
    return ""


def _bearer(token: str) -> str:
    parts = token.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def _api_key(scope: Scope) -> str:
    return _header(scope, "x-api-key") or _bearer(_header(scope, "authorization") or "")


def _client_ip(scope: Scope) -> str:
    xff = _header(scope, "x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else ""


_adapter = resolve_adapter_from_env()


def fetch_verdict(request: FastAPIRequest) -> str:
    """
    Pluggable verdict fetcher. Tests can monkeypatch this symbol.
    Default impl uses the resolved adapter and a normalized payload placed
    on request.state by this middleware.
    """
    payload = getattr(request.state, "normalized_payload", {})
    try:
        return _adapter.assess(payload)  # "safe" | "unsafe" | "unclear"
    except Exception:
        return "unclear"


class AbuseGateMiddleware:
    """ASGI middleware that consults AbuseEngine and attaches decision headers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: Optional[bool] = None,
        engine: Optional[AbuseEngine] = None,
        cfg: Optional[AbuseConfig] = None,
    ) -> None:
        self.app = app
        self.enabled = _enabled("ABUSE_GATE_ENABLED", True) if enabled is None else enabled
        self.engine = engine or AbuseEngine(cfg=cfg or AbuseConfig.from_env())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        api_key_raw = _api_key(scope)
        ip = _client_ip(scope) or "0.0.0.0"
        sub = Subject(api_key_hash=_hash(api_key_raw) if api_key_raw else "anon", ip_hash=_hash(ip))

        # For body-bearing methods, buffer the body once and replay downstream.
        body_bytes = b""
        inner_receive = receive
        if method in ("POST", "PUT", "PATCH"):
            body_bytes = await _read_body(receive)
            inner_receive = _replay_body(body_bytes, receive)

        # Put normalized payload on scope["state"] so Request.state sees it.
        state = scope.setdefault("state", {})
        try:
            # Build a Request against the same scope with the replay receive,
            # so downstream will still get the full body.
            req_for_payload = FastAPIRequest(scope, inner_receive)  # type: ignore[arg-type]
            state["normalized_payload"] = build_normalized_payload(req_for_payload, body_bytes)
        except Exception:
            state["normalized_payload"] = {}

        # Quarantine short-circuit
        mode_now = self.engine.current_mode(sub)
        if mode_now == "full_quarantine":
            await self._quarantine_response(sub, mode_now)(scope, inner_receive, send)
            return

        # Let the (pluggable) verifier decide
        req_for_verdict = FastAPIRequest(scope, inner_receive)  # type: ignore[arg-type]
        verdict = fetch_verdict(req_for_verdict)  # "safe" | "unsafe" | "unclear"

        decision: Decision = "allow"
        if verdict == "unsafe":
            decision = self.engine.record_unsafe(sub)
            if decision == "full_quarantine":
                await self._quarantine_response(sub, decision)(scope, inner_receive, send)
                return

        inc = generate_incident_id()
        hdrs = decision_headers(decision, inc, None)

        async def send_wrapped(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])
                for k, v in hdrs.items():
                    headers.append((k.encode("latin-1"), str(v).encode("latin-1")))
            await send(message)

        await self.app(scope, inner_receive, send_wrapped)

    # ------------------- helpers -------------------

    def _quarantine_response(self, sub: Subject, mode: Decision) -> JSONResponse:
        inc = generate_incident_id()
        retry = self.engine.retry_after_seconds(sub)
        hdrs = decision_headers(mode, inc, retry_after_s=retry)
        payload = {
            "code": "guardrail_quarantined",
            "detail": "access temporarily blocked due to harmful activity",
            "mode": mode,
            "retry_after_seconds": retry,
            "incident_id": inc,
        }
        resp = JSONResponse(payload, status_code=429)
        for k, v in hdrs.items():
            resp.headers[k] = str(v)
        return resp


async def _read_body(receive: Receive) -> bytes:
    chunks = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.request":
            body = message.get("body", b"")
            if body:
                chunks.append(body)
            more = message.get("more_body", False)
        else:
            # ignore other message types here
            more = False
    return b"".join(chunks)


def _replay_body(body: bytes, fallback: Receive) -> Receive:
    sent = {"done": False}

    async def _receive() -> dict:
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await fallback()

    return _receive
