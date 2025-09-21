from __future__ import annotations

import importlib
import os
import time
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.services.detectors.ingress_pipeline import _enabled as _flag_enabled

router = APIRouter(tags=["ops"])


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


def _check_redis() -> Dict[str, Any]:
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        return _ok("redis", {"configured": False})
    try:
        from app.observability import admin_audit as audit

        client = getattr(audit, "_redis_client", lambda: None)()
        pong = bool(client and client.ping())
    except Exception as exc:  # pragma: no cover - defensive
        return _fail(
            "redis",
            {"configured": True, "url": redis_url, "error": str(exc)},
        )
    detail = {"configured": True, "url": redis_url, "ping": pong}
    return _ok("redis", detail) if pong else _fail("redis", detail)


def _check_audit_file() -> Dict[str, Any]:
    from app import config

    audit_backend = (
        os.getenv("AUDIT_BACKEND", getattr(config, "AUDIT_BACKEND", ""))
        .strip()
        .lower()
    )
    audit_file_env = os.getenv("AUDIT_LOG_FILE", "")
    audit_file_config = getattr(config, "AUDIT_LOG_FILE", "")
    audit_file = audit_file_env or audit_file_config
    need_file = audit_backend == "file" or bool(audit_file)
    if not need_file:
        return _ok("audit_file", {"configured": False})
    if not audit_file:
        return _fail("audit_file", {"configured": True, "error": "path not set"})
    try:
        directory = os.path.dirname(audit_file) or "."
        dir_ok = os.path.isdir(directory)
        writable = False
        try:
            with open(audit_file, "a", encoding="utf-8"):
                pass
            writable = True
        except Exception:
            writable = False
        detail = {"path": audit_file, "dir_ok": dir_ok, "writable": writable}
        return _ok("audit_file", detail) if dir_ok and writable else _fail("audit_file", detail)
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("audit_file", {"path": audit_file, "error": str(exc)})


def _check_mitigation_file() -> Dict[str, Any]:
    backend = os.getenv("MITIGATION_STORE_BACKEND", "").strip().lower()
    path = os.getenv("MITIGATION_STORE_FILE", "")
    if backend != "file" or not path:
        return _ok("mitigation_file", {"configured": False})
    try:
        directory = os.path.dirname(path) or "."
        dir_ok = os.path.isdir(directory)
        writable = False
        try:
            with open(path, "a", encoding="utf-8"):
                pass
            writable = True
        except Exception:
            writable = False
        detail = {"path": path, "dir_ok": dir_ok, "writable": writable}
        if dir_ok and writable:
            return _ok("mitigation_file", detail)
        return _fail("mitigation_file", detail)
    except Exception as exc:  # pragma: no cover - defensive
        return _fail("mitigation_file", {"path": path, "error": str(exc)})


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
    payload = {"status": "ok", "ok": True, "time": time.time()}
    return JSONResponse(payload)


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    app = request.app
    checks: Dict[str, Any] = {}
    checks.update(_check_policy())
    checks.update(_check_decisions_provider())
    checks.update(_check_webhooks())
    checks.update(_check_ratelimit_backend(app))
    checks.update(_check_metrics_route(app))
    checks.update(_check_redis())
    checks.update(_check_audit_file())
    checks.update(_check_mitigation_file())

    overall = "ok"
    for value in checks.values():
        if isinstance(value, dict) and value.get("status") == "fail":
            overall = "fail"
            break

    status_code = 200 if overall == "ok" else 503
    payload = {"status": overall, "ok": overall == "ok", "checks": checks}
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
        "ok": True,
        "policy_version": _current_rules_version_safe(),
        "features": features,
    }
    return JSONResponse(payload)
