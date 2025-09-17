from __future__ import annotations

import importlib
import os
import time
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.services.detectors.ingress_pipeline import _enabled as _flag_enabled

router = APIRouter(tags=["system"])


def _ok(name: str, detail: Any | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "ok"}
    if detail is not None:
        payload["detail"] = detail
    return {name: payload}


def _fail(name: str, detail: Any | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "fail"}
    if detail is not None:
        payload["detail"] = detail
    return {name: payload}


def _has_metrics(app: Any) -> bool:
    try:
        for route in getattr(app.router, "routes", []):
            if getattr(route, "path", None) == "/metrics":
                return True
    except Exception:
        pass
    return False


def _check_policy() -> Dict[str, Any]:
    try:
        module = importlib.import_module("app.services.policy")
        if hasattr(module, "current_rules_version"):
            version = module.current_rules_version()
            if version:
                return _ok("policy", {"version": str(version)})
        if hasattr(module, "get_active_policy"):
            merged = module.get_active_policy()
            if merged:
                return _ok("policy", {"version": "unknown"})
        if hasattr(module, "get"):
            merged = module.get()
            if merged:
                return _ok("policy", {"version": "unknown"})
        return _fail("policy", "no active policy")
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("policy", f"exception: {type(exc).__name__}")


def _check_decisions_provider() -> Dict[str, Any]:
    try:
        module = importlib.import_module("app.routes.admin_decisions_api")
        provider_factory = getattr(module, "_get_provider", None)
        if callable(provider_factory):
            provider = provider_factory()
            items, total = provider(None, None, None, None, 1, 0)
            detail: Dict[str, Any] = {"total_hint": total}
            if items:
                detail["sample"] = items[0]
            return _ok("decisions", detail)
        return _ok("decisions", "provider not configured")
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("decisions", f"exception: {type(exc).__name__}")


def _check_webhooks() -> Dict[str, Any]:
    try:
        service = None
        for name in ("app.services.webhooks", "app.services.webhook"):
            try:
                service = importlib.import_module(name)
                break
            except Exception:
                continue
        if service is None:
            return _ok("webhooks", "service not present")

        dlq_len = None
        if hasattr(service, "dlq_size"):
            dlq_len = int(service.dlq_size())
        elif hasattr(service, "dlq_len"):
            dlq_len = int(service.dlq_len())

        breaker = None
        if hasattr(service, "breaker_snapshot"):
            breaker = service.breaker_snapshot()

        detail: Dict[str, Any] = {"dlq": dlq_len, "breaker": bool(breaker)}
        threshold_raw = os.getenv("WEBHOOK_DLQ_READY_THRESHOLD", "0")
        try:
            threshold = int(threshold_raw)
        except Exception:
            threshold = 0
        if dlq_len is not None and threshold >= 0 and dlq_len > threshold:
            detail["threshold"] = "WEBHOOK_DLQ_READY_THRESHOLD"
            return _fail("webhooks", detail)
        return _ok("webhooks", detail)
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("webhooks", f"exception: {type(exc).__name__}")


def _check_ratelimit_backend(app: Any) -> Dict[str, Any]:
    try:
        settings = getattr(app.state, "settings", None)
        backend = None
        if settings is not None:
            ingress = getattr(settings, "ingress", None)
            rate_limit = getattr(ingress, "rate_limit", None)
            backend = getattr(rate_limit, "backend", None)
        backend = backend or os.getenv("RATE_LIMIT_BACKEND", "memory")
        if str(backend).lower() != "redis":
            return _ok("ratelimit", {"backend": "memory"})

        try:
            module = importlib.import_module("app.services.ratelimit_redis")
            client_factory = getattr(module, "get_client", None)
            if callable(client_factory):
                client = client_factory()
                pong = client.ping()
                return _ok("ratelimit", {"backend": "redis", "ping": bool(pong)})
        except Exception:
            pass
        return _fail("ratelimit", "redis backend configured but client not available")
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("ratelimit", f"exception: {type(exc).__name__}")


def _check_metrics_route(app: Any) -> Dict[str, Any]:
    return _ok("metrics", {"route": _has_metrics(app)})


def _current_rules_version_safe() -> str:
    try:
        pol = importlib.import_module("app.services.policy")
        if hasattr(pol, "current_rules_version"):
            version = pol.current_rules_version()
            if version:
                return str(version)
    except Exception:  # pragma: no cover - defensive
        pass
    return "unknown"


@router.get("/livez")
async def livez() -> JSONResponse:
    return JSONResponse({"status": "ok", "time": time.time()})


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    app = request.app
    checks: Dict[str, Any] = {}
    checks.update(_check_policy())
    checks.update(_check_decisions_provider())
    checks.update(_check_webhooks())
    checks.update(_check_ratelimit_backend(app))
    checks.update(_check_metrics_route(app))

    overall = "ok"
    for value in checks.values():
        if isinstance(value, dict) and value.get("status") == "fail":
            overall = "fail"
            break

    status_code = 200 if overall == "ok" else 503
    payload = {"status": overall, "checks": checks}
    return JSONResponse(payload, status_code=status_code)


@router.get("/health")
async def health_alias(request: Request) -> JSONResponse:
    return await readyz(request)


@router.get("/healthz")
async def healthz() -> JSONResponse:
    features = {
        "pdf_detector": _flag_enabled("PDF_DETECTOR_ENABLED", True),
        "docx_detector": _flag_enabled("DOCX_DETECTOR_ENABLED", True),
        "image_safe_transform": _flag_enabled("IMAGE_SAFE_TRANSFORM_ENABLED", True),
    }
    payload = {
        "status": "ok",
        "policy_version": _current_rules_version_safe(),
        "features": features,
    }
    return JSONResponse(payload)
