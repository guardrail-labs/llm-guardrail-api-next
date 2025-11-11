# app/main.py
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import pkgutil
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from app import settings
from app.middleware.admin_session import AdminSessionMiddleware
from app.middleware.egress_output_inspect import EgressOutputInspectMiddleware
from app.middleware.egress_redact import EgressRedactMiddleware
from app.middleware.egress_timing import EgressTimingMiddleware
from app.middleware.guardrail_mode import GuardrailModeMiddleware, current_guardrail_mode
from app.middleware.header_canonicalize import HeaderCanonicalizeMiddleware
from app.middleware.idempotency import IdempotencyMiddleware
from app.middleware.ingress_archive_peek import IngressArchivePeekMiddleware
from app.middleware.ingress_decode import DecodeIngressMiddleware
from app.middleware.ingress_duplicate_header_guard import (
    IngressDuplicateHeaderGuardMiddleware,
)
from app.middleware.ingress_emoji_zwj import IngressEmojiZWJMiddleware
from app.middleware.ingress_header_limits import IngressHeaderLimitsMiddleware
from app.middleware.ingress_markup_plaintext import IngressMarkupPlaintextMiddleware
from app.middleware.ingress_metadata import IngressMetadataMiddleware
from app.middleware.ingress_path_guard import IngressPathGuardMiddleware
from app.middleware.ingress_probing import IngressProbingMiddleware
from app.middleware.ingress_risk import IngressRiskMiddleware
from app.middleware.ingress_token_scan import IngressTokenScanMiddleware
from app.middleware.ingress_trace_guard import IngressTraceGuardMiddleware
from app.middleware.ingress_unicode import UnicodeIngressSanitizer
from app.middleware.ingress_unicode_sanitizer import (
    IngressUnicodeSanitizerMiddleware,
)
from app.middleware.latency_instrument import LatencyMiddleware
from app.middleware.multimodal_middleware import MultimodalGateMiddleware
from app.middleware.quota import QuotaMiddleware
from app.middleware.request_id import RequestIDMiddleware, get_request_id
from app.middleware.stream_sse_guard import SSEGuardMiddleware
from app.middleware.tenant_bot import TenantBotMiddleware
from app.middleware.unicode_middleware import UnicodeSanitizerMiddleware
from app.middleware.unicode_normalize_guard import UnicodeNormalizeGuard
from app.observability.http_status import HttpStatusMetricsMiddleware
from app.routes.admin_scope_api import router as admin_scope_router
from app.routes.egress import router as egress_router
from app.runtime import idem_store
from app.services.bindings.utils import (
    compute_version_for_path as _compute_version_for_path,
    propagate_bindings as _propagate_bindings,
    read_policy_version as _read_policy_version,
)
from app.services.compliance.registry import ComplianceRegistry
from app.services.redis_runtime import runtime_warmup
from app.telemetry.tracing import TracingMiddleware

RequestHandler = Callable[[StarletteRequest], Awaitable[StarletteResponse]]

log = logging.getLogger(__name__)
_log = log


def _best_effort(msg: str, fn: Callable[[], Any]) -> None:
    """Invoke ``fn`` while ensuring failures are only logged at DEBUG."""

    try:
        fn()
    except Exception as exc:  # pragma: no cover - diagnostic only
        # nosec B110 - preserve historical "best effort" behavior while logging
        _log.debug("%s: %s", msg, exc)


def _remove_legacy_decisions_ndjson(app: FastAPI) -> None:
    try:
        from app.routes.admin_decisions_export import export_ndjson as _legacy_export_ndjson
    except Exception:
        return

    try:
        app.router.routes = [
            route
            for route in app.router.routes
            if getattr(route, "endpoint", None) is not _legacy_export_ndjson
        ]
    except Exception:
        return


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _parse_int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        v = int(raw)
        return v if v >= 0 else default
    except Exception:
        return default


_PRUNE_INTERVAL_SECONDS = _parse_int_env("DECISIONS_PRUNE_INTERVAL_SECONDS", 3600)


async def _prune_loop() -> None:
    interval = max(_PRUNE_INTERVAL_SECONDS, 1)
    while True:
        try:
            from app.services import decisions as decisions_store
        except Exception as exc:
            _log.debug("import decisions store failed: %s", exc)
        else:
            _best_effort("prune decisions", lambda: decisions_store.prune())
        try:
            await asyncio.sleep(interval)
        except Exception:
            return


def _start_prune_task(app: FastAPI) -> None:
    """
    Start the prune loop once. Safe to call from both lifespan and startup.
    """
    if getattr(app.state, "prune_task", None):
        return

    def _start() -> None:
        task = asyncio.create_task(_prune_loop())
        app.state.prune_task = task

    _best_effort("start prune loop", _start)


_RATE_HEADERS = ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")
_QUOTA_HEADERS = (
    "X-Quota-Day",
    "X-Quota-Hour",
    "X-Quota-Min",
    "X-Quota-Remaining",
    "X-Quota-Reset",
)


def _safe_headers_copy(src_headers) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for k, v in src_headers.raw:
            out.setdefault(k.decode("latin-1"), v.decode("latin-1"))
    except Exception as exc:
        _log.debug("copy raw headers failed: %s", exc)
        try:
            for k, v in src_headers.items():
                out.setdefault(k, v)
        except Exception as inner_exc:
            _log.debug("copy mapped headers failed: %s", inner_exc)
    rid: Optional[str] = None
    for key in list(out.keys()):
        if key.lower() == "x-request-id":
            rid = out[key]
            if key != "X-Request-ID":
                out.pop(key)
    rid = rid or get_request_id()
    if rid:
        out["X-Request-ID"] = rid
    now = int(time.time())
    defaults = {
        "X-RateLimit-Limit": "60",
        "X-RateLimit-Remaining": "3600",
        "X-RateLimit-Reset": str(now + 60),
    }
    quota_defaults = {
        "X-Quota-Day": "0",
        "X-Quota-Hour": "0",
        "X-Quota-Min": "0",
        "X-Quota-Remaining": "0",
        "X-Quota-Reset": "60",
    }
    for k in _RATE_HEADERS:
        out.setdefault(k, defaults[k])
    for k in _QUOTA_HEADERS:
        out.setdefault(k, quota_defaults[k])
    return out


def _ensure_idempotency_inner(app: FastAPI, *, finalize: bool = False) -> None:
    try:
        middleware = list(app.user_middleware)
    except Exception:
        return

    kept: list[Any] = []
    moved: list[Any] = []
    for entry in middleware:
        if getattr(entry, "cls", None) is IdempotencyMiddleware:
            moved.append(entry)
        else:
            kept.append(entry)

    if not moved:
        return

    try:
        app.user_middleware[:] = [*kept, *moved]
        if finalize:
            app.middleware_stack = app.build_middleware_stack()
        elif getattr(app, "middleware_stack", None) is not None:
            app.middleware_stack = None
    except Exception as exc:
        _log.debug("ensure idempotency middleware update failed: %s", exc)


class _NormalizeUnauthorizedMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: StarletteRequest, call_next: RequestHandler
    ) -> StarletteResponse:
        resp: StarletteResponse = await call_next(request)
        if resp.status_code != 401:
            return resp
        body_chunks: list[bytes] = []
        if hasattr(resp, "body_iterator") and resp.body_iterator is not None:
            async for chunk in resp.body_iterator:
                body_chunks.append(chunk)
        raw = b"".join(body_chunks) if body_chunks else b""
        detail: str = "Unauthorized"
        try:
            if raw:
                parsed = json.loads(raw.decode() or "{}")
                detail = str(parsed.get("detail", detail))
        except Exception as exc:
            _log.debug("normalize unauthorized parse failed: %s", exc)
        payload = {
            "code": "unauthorized",
            "detail": detail,
            "request_id": get_request_id() or "",
        }
        headers = _safe_headers_copy(resp.headers)
        headers.setdefault("WWW-Authenticate", "Bearer")
        return JSONResponse(payload, status_code=401, headers=headers)


class _CompatHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: StarletteRequest, call_next: RequestHandler
    ) -> StarletteResponse:
        resp: StarletteResponse = await call_next(request)
        if not resp.headers.get("X-Content-Type-Options"):
            resp.headers["X-Content-Type-Options"] = "nosniff"
        if not resp.headers.get("X-Frame-Options"):
            resp.headers["X-Frame-Options"] = "DENY"
        rp_env = os.getenv("SEC_HEADERS_REFERRER_POLICY")
        if not resp.headers.get("Referrer-Policy"):
            resp.headers["Referrer-Policy"] = rp_env if rp_env else "no-referrer"
        pp = os.getenv("SEC_HEADERS_PERMISSIONS_POLICY")
        if pp:
            resp.headers["Permissions-Policy"] = pp
        path = request.url.path
        if path.startswith("/guardrail") and not path.startswith("/v1/"):
            resp.headers.setdefault("Deprecation", "true")
        if _truthy(os.getenv("CORS_ENABLED", "0")):
            origin = request.headers.get("origin") or request.headers.get("Origin")
            if origin:
                allowed = [
                    o.strip()
                    for o in (os.getenv("CORS_ALLOW_ORIGINS") or "").split(",")
                    if o.strip()
                ]
                if "*" in allowed or origin in allowed:
                    resp.headers["Access-Control-Allow-Origin"] = origin
                    vary = resp.headers.get("Vary", "")
                    if "Origin" not in [v.strip() for v in vary.split(",") if v]:
                        resp.headers["Vary"] = f"{vary}, Origin" if vary else "Origin"
        return resp


def _include_all_route_modules(app: FastAPI) -> int:
    """Recursively include APIRouter objects under app.routes.

    Skips app.routes.egress (included manually) and any admin-focused modules to
    avoid double-registration; these are handled explicitly in ``create_app``.
    """
    try:
        routes_pkg = importlib.import_module("app.routes")
    except Exception:
        return 0
    visited: Set[str] = set()
    count = 0

    def _walk(package_mod) -> None:
        nonlocal count
        pkg_path = getattr(package_mod, "__path__", None)
        pkg_name = package_mod.__name__
        if not pkg_path:
            return
        for m in pkgutil.iter_modules(pkg_path, pkg_name + "."):
            name = m.name
            if name in visited:
                continue
            if name in {
                "app.routes.egress",
                "app.routes.admin",
                "app.routes.policy_admin",
                "app.routes.admin_policies",
                "app.routes.admin_rulepacks",
                "app.routes.admin_ui",
                "app.routes.health",
            }:
                visited.add(name)
                continue
            try:
                mod = importlib.import_module(name)
                visited.add(name)
            except Exception:
                _log.debug("module import failed: %s", name, exc_info=True)
                continue
            try:
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if isinstance(obj, APIRouter):
                        app.include_router(obj)
                        count += 1
            except Exception as exc:
                _log.debug("include routers from %s failed: %s", name, exc)
            try:
                if hasattr(mod, "__path__"):
                    _walk(mod)
            except Exception as exc:
                _log.debug("walk module failed: %s", name, exc)

    _walk(routes_pkg)
    return count


# -------------------- Admin bindings fallback + storage -----------------------

_BINDINGS: Dict[Tuple[str, str], Dict[str, str]] = {}


def _install_bindings_fallback(app: FastAPI) -> None:
    admin = APIRouter(prefix="/admin", tags=["admin-bindings-fallback"])

    def _require_admin_key(x_admin_key: Optional[str]) -> None:
        required = os.getenv("ADMIN_API_KEY")
        if required and (not x_admin_key or x_admin_key != required):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @admin.put("/bindings")
    async def put_bindings(
        payload: Dict[str, Any],
        x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    ) -> dict:
        _require_admin_key(x_admin_key)
        bindings_in = payload.get("bindings") or []
        if not isinstance(bindings_in, list):
            raise HTTPException(status_code=400, detail="Invalid payload")

        out: List[Dict[str, str]] = []
        for item in bindings_in:
            tenant = str(item.get("tenant") or "").strip()
            bot = str(item.get("bot") or "").strip()
            rules_path = str(item.get("rules_path") or "").strip()
            if not tenant or not bot or not rules_path:
                raise HTTPException(status_code=400, detail="Missing tenant/bot/rules_path")
            version = _compute_version_for_path(rules_path)
            policy_version = _read_policy_version(rules_path) or version
            rec = {
                "tenant": tenant,
                "bot": bot,
                "rules_path": rules_path,
                "version": version,
                "policy_version": policy_version,
            }
            _BINDINGS[(tenant, bot)] = {
                "rules_path": rules_path,
                "version": version,
                "policy_version": policy_version,
            }
            out.append(rec)
        _best_effort("propagate bindings", lambda: _propagate_bindings(out))
        return {"bindings": out}

    @admin.get("/bindings")
    async def list_bindings() -> Dict[str, Any]:
        items: List[Dict[str, str]] = []
        for (tenant, bot), rec in sorted(_BINDINGS.items()):
            items.append(
                {
                    "tenant": tenant,
                    "bot": bot,
                    "rules_path": rec["rules_path"],
                    "version": rec["version"],
                    "policy_version": rec.get("policy_version") or rec["version"],
                }
            )
        return {"bindings": items}

    @admin.get("/bindings/resolve")
    async def get_binding(
        tenant: str = Query(...),
        bot: str = Query(...),
        x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    ) -> dict:
        _require_admin_key(x_admin_key)
        rec = _BINDINGS.get((tenant, bot))
        if not rec:
            raise HTTPException(status_code=404, detail="Not Found")
        return {
            "tenant": tenant,
            "bot": bot,
            "rules_path": rec["rules_path"],
            "version": rec["version"],
            "policy_version": rec.get("policy_version") or rec["version"],
        }

    @admin.delete("/bindings")
    async def delete_binding(
        tenant: str = Query(...),
        bot: str = Query(...),
        x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    ) -> dict:
        _require_admin_key(x_admin_key)
        _BINDINGS.pop((tenant, bot), None)
        items: List[Dict[str, str]] = []
        for (t, b), rec in sorted(_BINDINGS.items()):
            items.append(
                {
                    "tenant": t,
                    "bot": b,
                    "rules_path": rec["rules_path"],
                    "version": rec["version"],
                    "policy_version": rec.get("policy_version") or rec["version"],
                }
            )
        return {"bindings": items}

    app.include_router(admin)


# ---------------- Bindings-aware guard for POST /guardrail --------------------


def _extract_block_tokens_from_yaml(p: str) -> List[str]:
    tokens: List[str] = []
    try:
        import yaml

        data = yaml.safe_load(Path(p).read_text(encoding="utf-8"))
    except Exception:
        data = None

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(k, str) and k.lower() in {"block", "deny_if_contains"}:
                    if isinstance(v, list):
                        for i in v:
                            if isinstance(i, str):
                                tokens.append(i)
                    elif isinstance(v, str):
                        tokens.append(v)
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)
        elif isinstance(x, str):
            tokens.append(x)

    walk(data)
    seen: Set[str] = set()
    out: List[str] = []
    for t in tokens:
        s = t.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


class _BindingsGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: StarletteRequest, call_next: RequestHandler
    ) -> StarletteResponse:
        if request.method == "POST" and request.url.path == "/guardrail":
            tenant = request.headers.get("X-Tenant-ID") or request.headers.get("X-Tenant-Id")
            bot = request.headers.get("X-Bot-ID") or request.headers.get("X-Bot-Id")
            rec = _BINDINGS.get(((tenant or ""), (bot or "")))
            if rec and "application/json" in (request.headers.get("content-type") or "").lower():
                body_bytes = await request.body()
                try:
                    payload = json.loads(body_bytes.decode("utf-8") or "{}")
                except Exception:
                    payload = {}
                prompt = str(payload.get("prompt") or "")
                tokens = _extract_block_tokens_from_yaml(rec["rules_path"])
                if any(t and t in prompt for t in tokens):
                    return JSONResponse(
                        {
                            "decision": "block",
                            "policy_version": rec.get("policy_version") or rec.get("version"),
                            "rules_path": rec.get("rules_path"),
                        },
                        status_code=200,
                    )

                async def _receive():
                    return {"type": "http.request", "body": body_bytes, "more_body": False}

                setattr(request, "_receive", _receive)

        return await call_next(request)


# ------------------------ Error helpers & app factory -------------------------


def _status_code_to_code(status: int) -> str:
    if status == 400:
        return "bad_request"
    if status == 401:
        return "unauthorized"
    if status == 404:
        return "not_found"
    if status == 413:
        return "payload_too_large"
    if status == 429:
        return "rate_limited"
    return "internal_error"


def _json_error(detail: str, status: int, base_headers=None) -> JSONResponse:
    payload = {
        "code": _status_code_to_code(status),
        "detail": detail,
        "request_id": get_request_id() or "",
    }
    headers = _safe_headers_copy(base_headers or {})
    rid = payload.get("request_id")
    if rid:
        headers.setdefault("X-Request-ID", rid)
    mode = current_guardrail_mode()
    if mode:
        headers.setdefault("X-Guardrail-Mode", mode)
    return JSONResponse(payload, status_code=status, headers=headers)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.routes import system as sysmod

    _webhooks_module = None

    try:
        await runtime_warmup()
    except Exception as exc:
        _log.debug("runtime warmup failed: %s", exc)

    try:
        app.state.compliance_registry = ComplianceRegistry()
    except Exception as exc:
        _log.debug("compliance registry init failed: %s", exc)

    # Fail fast if probe is enabled but required env vars are missing.
    if sysmod._probe_enabled():
        missing = [k for k in sysmod._probe_required_envs() if not os.getenv(k)]
        if missing:
            raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")

    # Best-effort pre-warm of rulepacks and bindings so first request isn't slow.
    try:
        from app.services import rulepacks_engine
    except Exception as exc:
        _log.debug("import rulepacks_engine failed: %s", exc)
    else:
        _best_effort(
            "compile active rulepacks", lambda: rulepacks_engine.compile_active_rulepacks()
        )
    try:
        from app.services.config_store import load_bindings
    except Exception as exc:
        _log.debug("import load_bindings failed: %s", exc)
    else:
        _best_effort("load bindings", lambda: load_bindings())

    # Initialize decisions store and start prune loop (duplicate-safe)
    try:
        from app.services import decisions as decisions_store
    except Exception as exc:
        _log.debug("import decisions store failed: %s", exc)
    else:
        _best_effort("ensure decisions store ready", lambda: decisions_store.ensure_ready())

    _start_prune_task(app)

    try:
        from app.services import webhooks as _wh_mod
    except Exception as exc:
        _log.debug("import webhooks module failed: %s", exc)
        _webhooks_module = None
    else:
        try:
            _wh_mod.ensure_started()
        except Exception as exc:
            _log.debug("webhooks ensure started failed: %s", exc)
            _webhooks_module = None
        else:
            _webhooks_module = _wh_mod

    await sysmod._startup_readiness()
    try:
        yield
    finally:
        await sysmod._shutdown_readiness()
        if _webhooks_module is not None:
            _best_effort("webhooks module shutdown", lambda: _webhooks_module.shutdown())
        else:
            try:
                from app.services import webhooks as _wh_mod
            except Exception as exc:
                _log.debug("import webhooks module for shutdown failed: %s", exc)
            else:
                _best_effort("webhooks module shutdown", lambda: _wh_mod.shutdown())
        # Stop prune loop gracefully if running
        try:
            task = getattr(app.state, "prune_task", None)
            if task:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
                app.state.prune_task = None
        except Exception as exc:
            _log.debug("prune loop shutdown failed: %s", exc)
        # Clean shutdown for tracer/exporter if present.
        try:
            from opentelemetry import trace as _trace

            provider = _trace.get_tracer_provider()
            shutdown = getattr(provider, "shutdown", None)
            if callable(shutdown):
                shutdown()
        except Exception as exc:
            _log.debug("tracer shutdown failed: %s", exc)
        try:
            from app import runtime as _runtime
        except Exception as exc:
            _log.debug("import runtime for shutdown failed: %s", exc)
        else:
            try:
                await _runtime.close_redis_connections()
            except Exception as exc:
                _log.debug("redis shutdown failed: %s", exc)


OPENAPI_TAGS = [
    {"name": "health", "description": "Liveness and readiness probes"},
    {"name": "decisions", "description": "Decision listing and exports"},
    {"name": "adjudications", "description": "Adjudication listing and exports"},
    {"name": "admin", "description": "Admin operations (CSRF-protected)"},
]


def create_app() -> FastAPI:
    app = FastAPI(
        title="LLM Guardrail API",
        description="Policy enforcement, adjudication, and observability for LLM apps.",
        version="1.0.0",
        contact={"name": "Guardrail Team"},
        license_info={"name": "Apache-2.0"},
        lifespan=lifespan,
        openapi_tags=OPENAPI_TAGS,
    )
    try:
        from app.security.rbac import RBACError
    except Exception as exc:
        _log.debug("import RBACError failed: %s", exc)
    else:

        async def handle_rbac_error(request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(status_code=403, content={"detail": str(exc)})

        _best_effort(
            "install RBAC error handler",
            lambda: app.add_exception_handler(RBACError, handle_rbac_error),
        )
    try:
        from app.routes import health

        app.include_router(health.router)
    except Exception as exc:
        log.warning("Health routes unavailable: %s", exc)
    app.include_router(admin_scope_router)
    try:
        from app.routes.admin_idempotency import router as admin_idempotency_router
        from app.routes.admin_policy_packs import router as admin_policy_packs_router
    except Exception as exc:
        _log.debug("import admin_policy_packs_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_policy_packs_router",
            lambda: app.include_router(admin_policy_packs_router),
        )
        _best_effort(
            "include admin_idempotency_router",
            lambda: app.include_router(admin_idempotency_router),
        )
    try:
        from app.routes.admin_decisions_api import router as admin_decisions_router
    except Exception as exc:
        _log.debug("import admin_decisions_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_decisions_router",
            lambda: app.include_router(admin_decisions_router),
        )
    try:
        from app.routes.admin_decisions_export import (
            router as admin_decisions_export_router,
        )
    except Exception as exc:
        _log.debug("import admin_decisions_export_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_decisions_export_router",
            lambda: app.include_router(admin_decisions_export_router),
        )
    try:
        from app.routes.admin_overview import router as admin_overview_router
    except Exception as exc:
        _log.debug("import admin_overview_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_overview_router",
            lambda: app.include_router(admin_overview_router),
        )
    try:
        from app.routes.admin_apply_demo_defaults import (
            router as admin_apply_demo_defaults_router,
        )
    except Exception as exc:
        _log.debug("import admin_apply_demo_defaults_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_apply_demo_defaults_router",
            lambda: app.include_router(admin_apply_demo_defaults_router),
        )
    try:
        from app.routes.admin_apply_golden import (
            router as admin_apply_golden_router,
        )
    except Exception as exc:
        _log.debug("import admin_apply_golden_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_apply_golden_router",
            lambda: app.include_router(admin_apply_golden_router),
        )
    try:
        from app.routes.admin_apply_strict_secrets import (
            router as admin_apply_strict_secrets_router,
        )
    except Exception as exc:
        _log.debug("import admin_apply_strict_secrets_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_apply_strict_secrets_router",
            lambda: app.include_router(admin_apply_strict_secrets_router),
        )
    try:
        from app.routes import admin_secrets_strict

        app.include_router(admin_secrets_strict.router)
    except Exception as exc:
        log.warning("Admin secrets strict routes unavailable: %s", exc)
    try:
        from app.routes import admin_audit_api

        app.include_router(admin_audit_api.router)
    except Exception as exc:  # pragma: no cover - optional dependency
        log.warning("Admin audit API unavailable: %s", exc)
    try:
        from app.routes import admin_audit

        app.include_router(admin_audit.router)
    except Exception as exc:
        log.warning("Admin audit export bundle unavailable: %s", exc)
    try:
        from app.routes import admin_audit_export

        app.include_router(admin_audit_export.router)
    except Exception as exc:
        log.warning("Admin audit export unavailable: %s", exc)
    try:
        from app.routes import admin_data_lifecycle

        app.include_router(admin_data_lifecycle.router)
    except Exception as exc:
        log.warning("Data lifecycle routes unavailable: %s", exc)
    try:
        from app.routes import admin_features
    except Exception as exc:
        _log.debug("import admin_features failed: %s", exc)
    else:
        _best_effort("include admin_features", lambda: app.include_router(admin_features.router))
    # Optional auth/OIDC helpers
    try:
        from app.routes import admin_auth_oidc

        app.include_router(admin_auth_oidc.router)
    except Exception as exc:
        log.warning("OIDC routes unavailable: %s", exc)
    try:
        from app.routes import admin_me

        app.include_router(admin_me.router)
    except Exception as exc:
        log.warning("Admin /me route unavailable: %s", exc)
    # Starlette executes middleware in reverse registration order.
    # Desired runtime ingress order:
    #   PathGuard -> HeaderCanonicalize -> HeaderLimits -> DuplicateHeaderGuard
    #   -> UnicodeIngressSanitizerMiddleware -> TraceGuard -> Metadata
    #   -> (OTEL) -> RequestID
    # Register in inverse order to achieve this at runtime:
    app.add_middleware(RequestIDMiddleware)
    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)
    app.add_middleware(IngressMetadataMiddleware)
    app.add_middleware(IngressTraceGuardMiddleware)
    app.add_middleware(IngressUnicodeSanitizerMiddleware)
    app.add_middleware(IngressDuplicateHeaderGuardMiddleware)
    app.add_middleware(IngressHeaderLimitsMiddleware)
    app.add_middleware(HeaderCanonicalizeMiddleware)
    app.add_middleware(IngressPathGuardMiddleware)
    app.add_middleware(UnicodeIngressSanitizer)
    app.add_middleware(UnicodeSanitizerMiddleware)
    app.add_middleware(MultimodalGateMiddleware)
    app.add_middleware(DecodeIngressMiddleware)
    # Tokenizer-aware scanning for split sensitive terms
    app.add_middleware(IngressTokenScanMiddleware)
    # Emoji ZWJ/TAG detector to surface hidden ASCII
    app.add_middleware(IngressEmojiZWJMiddleware)
    # Extract plaintext from HTML/SVG so scanners can evaluate true text
    app.add_middleware(IngressMarkupPlaintextMiddleware)
    # Peek into small base64 archives to expose filenames and text samples
    app.add_middleware(IngressArchivePeekMiddleware)
    # Probing/leakage heuristics (rate + pattern + near-duplicate)
    app.add_middleware(IngressProbingMiddleware)
    # Session risk scoring after scanners (does not mutate payload)
    app.add_middleware(IngressRiskMiddleware)
    # Egress: inspect text/JSON outputs for hidden controls/markup (no mutation)
    app.add_middleware(EgressOutputInspectMiddleware)

    # SSE header hygiene must execute *before* compression on responses.
    # Therefore, register it *before* compression middleware so it runs later
    # on the request path but earlier on the response path.
    app.add_middleware(SSEGuardMiddleware)

    # --- Compression (if enabled) ---
    try:
        comp_mod = __import__("app.middleware.compression", fromlist=["install_compression"])
    except Exception as exc:
        _log.debug("import compression middleware failed: %s", exc)
    else:
        try:
            comp_mod.install_compression(app)
        except Exception as exc:
            _log.debug("install compression middleware failed: %s", exc)

    try:
        from starlette.middleware.gzip import GZipMiddleware as _StarletteGZip
    except Exception as exc:
        _log.debug("configure gzip middleware failed: %s", exc)
    else:
        if _truthy(os.getenv("COMPRESSION_ENABLED", "0")):
            app.add_middleware(
                _StarletteGZip,
                minimum_size=_parse_int_env("COMPRESSION_MIN_SIZE_BYTES", 0),
            )

    # Final egress stage: normalize timing for sensitive responses
    app.add_middleware(EgressTimingMiddleware)
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(EgressRedactMiddleware)
    app.add_middleware(TenantBotMiddleware)
    app.add_middleware(AdminSessionMiddleware)

    # Max body size (intercepts early)
    try:
        max_body_mod = __import__("app.middleware.max_body", fromlist=["install_max_body"])
    except Exception as exc:
        _log.debug("import max_body middleware failed: %s", exc)
    else:
        _best_effort("install max body middleware", lambda: max_body_mod.install_max_body(app))

    app.add_middleware(LatencyMiddleware)
    app.add_middleware(_NormalizeUnauthorizedMiddleware)
    app.add_middleware(HttpStatusMetricsMiddleware)
    if settings.IDEMP_ENABLED:
        app.add_middleware(
            IdempotencyMiddleware,
            store=idem_store(),
            ttl_s=settings.IDEMP_TTL_SECONDS,
            methods=settings.IDEMP_METHODS,
            max_body=settings.IDEMP_MAX_BODY_BYTES,
            cache_streaming=settings.IDEMP_CACHE_STREAMING,
            tenant_provider=lambda scope: "default",
            touch_on_replay=settings.IDEMP_TOUCH_ON_REPLAY,
        )

    # --- Admin bindings: prefer real router, else fallback ---
    admin_router = None
    try:
        from app.routes import admin as _admin_mod
    except Exception as exc:
        _log.debug("import admin router failed: %s", exc)
        try:
            from app.routes.admin.bindings import router as _bindings_router
        except Exception as inner_exc:
            _log.debug("import admin bindings router failed: %s", inner_exc)
            admin_router = None
        else:
            admin_router = _bindings_router
    else:
        admin_router = getattr(_admin_mod, "router", None)
    if admin_router is not None:
        app.include_router(admin_router)
    else:
        _install_bindings_fallback(app)

    # --- Explicit admin/policy routers (avoid walker dupes) ---
    try:
        from app.routes import policy_admin
    except Exception as exc:
        _log.debug("import policy_admin failed (optional): %s", exc)
    else:
        _best_effort(
            "include policy_admin",
            lambda: app.include_router(policy_admin.router),
        )

    try:
        from app.routes import (
            admin_adjudications,
            admin_adjudications_api,
            admin_config,
            admin_config_history,
            admin_decisions,
            admin_echo,
            admin_metrics_overrides,
            admin_policies,
            admin_retention,
            admin_rulepacks,
            admin_service_tokens,
            admin_ui,
            admin_webhook,
            admin_webhook_replay,
            admin_webhooks,
            admin_webhooks_dlq,
        )

        app.include_router(admin_decisions.router)
        app.include_router(admin_policies.router)
        app.include_router(admin_rulepacks.router)
        app.include_router(admin_ui.router)
        app.include_router(admin_config.router)
        app.include_router(admin_config_history.router)
        app.include_router(admin_webhook.router)
        app.include_router(admin_webhook_replay.router)
        app.include_router(admin_webhooks.router)
        app.include_router(admin_webhooks_dlq.router)
        app.include_router(admin_echo.router)
        app.include_router(admin_metrics_overrides.router)
        app.include_router(admin_service_tokens.router)
        app.include_router(admin_adjudications.router)
        app.include_router(admin_adjudications_api.router)
        app.include_router(admin_retention.router)
    except Exception as exc:
        _log.debug("bulk admin router include failed: %s", exc, exc_info=True)

    exports_loaded = False
    try:
        from app.routes import admin_export_adjudications, admin_export_decisions

        app.include_router(admin_export_decisions.router)
        app.include_router(admin_export_adjudications.router)
        exports_loaded = True
    except Exception as exc:
        log.warning("Admin export routes unavailable: %s", exc)

    # Persist the outcome on the app instance for any downstream checks
    app.state.exports_loaded_exports = exports_loaded

    # Remove the legacy route only if new exports are available
    if app.state.exports_loaded_exports:
        _remove_legacy_decisions_ndjson(app)

    # Admin Policy API (version + reload)
    try:
        from app.routes import admin_policy_api
    except Exception as exc:
        _log.debug("import admin_policy_api failed: %s", exc)
    else:
        _best_effort(
            "include admin_policy_api",
            lambda: app.include_router(admin_policy_api.router),
        )

    try:
        from app.routes.admin_policy_validate import (
            router as admin_policy_validate_router,
        )
    except Exception as exc:
        _log.debug("import admin_policy_validate_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_policy_validate_router",
            lambda: app.include_router(admin_policy_validate_router),
        )

    try:
        from app.routes.admin_mitigations import router as admin_mitigations_router
    except Exception as exc:
        _log.debug("import admin_mitigations_router failed: %s", exc)
    else:
        _best_effort(
            "include admin_mitigations_router",
            lambda: app.include_router(admin_mitigations_router),
        )

    try:
        # Lazy import so optional admin deps don’t crash startup at module import time.
        from app.routes import (
            admin_mitigation as admin_mitigation_module,
            admin_mitigation_modes,
        )
    except Exception as exc:
        _log.debug("import admin mitigation modules failed: %s", exc)
    else:
        _best_effort(
            "include admin_mitigation_module",
            lambda: app.include_router(admin_mitigation_module.router),
        )
        _best_effort(
            "include admin_mitigation_modes",
            lambda: app.include_router(admin_mitigation_modes.router),
        )

    # --- Remaining routers (walker skips egress + all admin variants) ---
    _include_all_route_modules(app)

    try:
        from app.admin_config.demo_seed import seed_demo_defaults
    except Exception as exc:
        _log.debug("import seed_demo_defaults failed: %s", exc)
    else:
        _best_effort("seed demo defaults", seed_demo_defaults)

    try:
        from app.routes import guardrail as guardrail_routes
    except Exception as exc:
        _log.debug("import guardrail routes failed: %s", exc)
    else:
        _best_effort(
            "include guardrail routes",
            lambda: app.include_router(
                guardrail_routes.router,
                prefix="/v1",
                tags=["guardrail", "v1"],
            ),
        )

    # --- Public egress route once ---
    app.include_router(egress_router)

    # Guard after request id & before handlers
    app.add_middleware(_BindingsGuardMiddleware)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        return _json_error(str(exc.detail), exc.status_code, base_headers=request.headers)

    @app.exception_handler(Exception)
    async def _internal_exc_handler(request: Request, exc: Exception):
        return _json_error("Internal Server Error", 500, base_headers=request.headers)

    app.add_middleware(_CompatHeadersMiddleware)

    from app.middleware.egress_guard import EgressGuardMiddleware
    from app.middleware.json_logging import install_json_logging

    app.add_middleware(EgressGuardMiddleware)
    try:
        from app.middleware.decision_headers import DecisionHeaderMiddleware
    except Exception as exc:
        _log.debug("import DecisionHeaderMiddleware failed: %s", exc)
    else:
        _best_effort(
            "add DecisionHeaderMiddleware",
            lambda: app.add_middleware(DecisionHeaderMiddleware),
        )
    install_json_logging(app)
    app.add_middleware(
        UnicodeNormalizeGuard,
        default_mode=os.getenv("CONFUSABLES_MODE", settings.CONFUSABLES_MODE),
        norm_form=os.getenv("CONFUSABLES_FORM", settings.CONFUSABLES_FORM),
        max_body_bytes=int(
            os.getenv(
                "CONFUSABLES_MAX_BODY_BYTES",
                str(settings.CONFUSABLES_MAX_BODY_BYTES),
            )
        ),
    )
    try:
        from app.middleware.rate_limit import RateLimitMiddleware
    except Exception as exc:
        _log.debug("import RateLimitMiddleware failed: %s", exc)
    else:
        _best_effort(
            "add RateLimitMiddleware",
            # Register late so it executes early (before body-heavy ingress guards).
            lambda: app.add_middleware(RateLimitMiddleware),
        )
    app.add_middleware(GuardrailModeMiddleware)
    _ensure_idempotency_inner(app)

    # ---- Ensure only our /metrics is registered and uses v0.0.4 ----
    try:
        from starlette.routing import Route

        app.router.routes = [
            r
            for r in app.router.routes
            if not (isinstance(r, Route) and getattr(r, "path", "") == "/metrics")
        ]
    except Exception as exc:
        _log.debug("prune legacy metrics route failed: %s", exc)
    try:
        from app.routes.metrics import router as _metrics_router
    except Exception as exc:
        _log.debug("import metrics router failed: %s", exc)
    else:
        _best_effort(
            "include metrics router",
            lambda: app.include_router(_metrics_router),
        )

    try:
        from app.routes import version

        app.include_router(version.router)
    except Exception as exc:
        log.warning("Version route unavailable: %s", exc)

    # Ensure there is no unconditional legacy removal here or at module import time.
    # If needed elsewhere, always guard with:
    # if getattr(app.state, "exports_loaded_exports", False):
    #     _remove_legacy_decisions_ndjson(app)
    if getattr(app.state, "exports_loaded_exports", False):
        _remove_legacy_decisions_ndjson(app)

    return app


build_app = create_app
app = create_app()


@app.on_event("startup")
async def _start_prune() -> None:
    _start_prune_task(app)


# ---- Existing PR includes preserved below ----

sec_headers_mod = __import__(
    "app.middleware.security_headers", fromlist=["install_security_headers"]
)
sec_headers_mod.install_security_headers(app)

security_mod = __import__("app.middleware.security", fromlist=["install_security"])
security_mod.install_security(app)

admin_router = __import__("app.admin.router", fromlist=["router"]).router
app.include_router(admin_router)

nosniff_mod = __import__("app.middleware.nosniff", fromlist=["install_nosniff"])
nosniff_mod.install_nosniff(app)

cors_mod = __import__("app.middleware.cors", fromlist=["install_cors"])
cors_mod.install_cors(app)

cors_fb_mod = __import__("app.middleware.cors_fallback", fromlist=["install_cors_fallback"])
cors_fb_mod.install_cors_fallback(app)

csp_mod = __import__("app.middleware.csp", fromlist=["install_csp"])
csp_mod.install_csp(app)

if getattr(app.state, "exports_loaded_exports", False):
    _remove_legacy_decisions_ndjson(app)

_ensure_idempotency_inner(app, finalize=True)
