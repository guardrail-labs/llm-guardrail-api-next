# app/main.py
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import pkgutil
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from app.metrics.route_label import route_label
from app.middleware.egress_redact import EgressRedactMiddleware
from app.middleware.quota import QuotaMiddleware
from app.middleware.request_id import RequestIDMiddleware, get_request_id
from app.middleware.tenant_bot import TenantBotMiddleware
from app.observability.http_status import HttpStatusMetricsMiddleware
from app.routes.egress import router as egress_router
from app.telemetry.tracing import TracingMiddleware

# Prometheus (optional; tests expect metrics but we guard imports)
try:  # pragma: no cover
    from prometheus_client import (
        REGISTRY as _PromRegistryObj,
        Histogram as _PromHistogramCls,
    )
    PromHistogram: Any | None = _PromHistogramCls
    PromRegistry: Any | None = _PromRegistryObj
except Exception:  # pragma: no cover
    PromHistogram = None
    PromRegistry = None

RequestHandler = Callable[[StarletteRequest], Awaitable[StarletteResponse]]


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _parse_int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        v = int(raw)
        return v if v >= 0 else default
    except Exception:
        return default


def _get_or_create_latency_histogram() -> Optional[Any]:
    if PromHistogram is None or PromRegistry is None:  # pragma: no cover
        return None
    name = "guardrail_latency_seconds"
    try:
        names_map = getattr(PromRegistry, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if existing is not None:
                return existing
    except Exception:
        pass
    try:
        return PromHistogram(name, "Request latency in seconds", ["route", "method"])
    except ValueError:
        try:
            names_map = getattr(PromRegistry, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                return names_map.get(name)
        except Exception:
            return None
        return None


class _LatencyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._hist = _get_or_create_latency_histogram()

    async def dispatch(
        self, request: StarletteRequest, call_next: RequestHandler
    ) -> StarletteResponse:
        start = time.perf_counter()
        try:
            return await call_next(request)
        finally:
            if self._hist is not None:
                try:
                    dur = max(time.perf_counter() - start, 0.0)
                    safe_route = route_label(request.url.path)
                    self._hist.labels(route=safe_route, method=request.method).observe(dur)
                except Exception:
                    pass


_RATE_HEADERS = ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")


def _safe_headers_copy(src_headers) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for k, v in src_headers.raw:
            out.setdefault(k.decode("latin-1"), v.decode("latin-1"))
    except Exception:
        try:
            for k, v in src_headers.items():
                out.setdefault(k, v)
        except Exception:
            pass
    rid = out.get("X-Request-ID") or (get_request_id() or "")
    if rid:
        out["X-Request-ID"] = rid
    now = int(time.time())
    defaults = {
        "X-RateLimit-Limit": "60",
        "X-RateLimit-Remaining": "3600",
        "X-RateLimit-Reset": str(now + 60),
    }
    for k in _RATE_HEADERS:
        out.setdefault(k, defaults[k])
    return out


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
        except Exception:
            pass
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


async def _prune_loop() -> None:
    await asyncio.sleep(10)
    try:
        from app.services import decisions as decisions_store

        while True:
            try:
                decisions_store.prune()
            except Exception:
                pass
            await asyncio.sleep(24 * 60 * 60)
    except Exception:
        return


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
                continue
            try:
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if isinstance(obj, APIRouter):
                        app.include_router(obj)
                        count += 1
            except Exception:
                pass
            try:
                if hasattr(mod, "__path__"):
                    _walk(mod)
            except Exception:
                pass

    _walk(routes_pkg)
    return count


# -------------------- Admin bindings fallback + storage -----------------------

_BINDINGS: Dict[Tuple[str, str], Dict[str, str]] = {}


def _compute_version_for_path(p: str) -> str:
    try:
        fp = Path(p)
        if fp.is_file():
            data = fp.read_bytes()
            return hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        pass
    return hashlib.sha256(p.encode("utf-8")).hexdigest()[:16]


def _read_policy_version(p: str) -> Optional[str]:
    try:
        import yaml
    except Exception:
        return None
    try:
        loaded = yaml.safe_load(Path(p).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            for key in ("policy_version", "version"):
                v = loaded.get(key)
                if isinstance(v, (str, int, float)):
                    return str(v)
    except Exception:
        return None
    return None


def _propagate_bindings(bindings: List[Dict[str, str]]) -> None:
    """
    Try to update whichever internal registry exists so the rest of the app
    respects the bindings (best effort; ignore failures).
    """
    module_candidates = [
        "app.services.rulepacks.bindings",
        "app.services.rulepacks_bindings",
        "app.services.bindings",
        "app.policy.bindings",
        "app.services.rulepacks_engine",
    ]
    func_candidates: List[str] = [
        "set_bindings",
        "apply_bindings",
        "update_bindings",
        "install_bindings",
    ]
    for mod_name in module_candidates:
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue
        for fn_name in func_candidates:
            fn = getattr(mod, fn_name, None)
            if fn and callable(fn):
                try:
                    fn(bindings)
                    return
                except Exception:
                    pass
        for attr in ("BINDINGS", "_BINDINGS"):
            if hasattr(mod, attr):
                try:
                    setattr(mod, attr, bindings)
                    return
                except Exception:
                    pass


def _install_bindings_fallback(app: FastAPI) -> None:
    admin = APIRouter(prefix="/admin", tags=["admin-bindings-fallback"])

    def _require_admin_key(x_admin_key: Optional[str]) -> None:
        required = os.getenv("ADMIN_API_KEY")
        if required and (not x_admin_key or x_admin_key != required):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @admin.put("/bindings")
    async def put_bindings(
        payload: dict,
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
        try:
            _propagate_bindings(out)
        except Exception:
            pass
        return {"bindings": out}

    @admin.get("/bindings")
    async def list_bindings() -> dict:
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
    headers["X-Request-ID"] = payload["request_id"]
    return JSONResponse(payload, status_code=status, headers=headers)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.routes import system as sysmod

    # Ensure latency histogram is registered once.
    _get_or_create_latency_histogram()

    # Fail fast if probe is enabled but required env vars are missing.
    if sysmod._probe_enabled():
        missing = [k for k in sysmod._probe_required_envs() if not os.getenv(k)]
        if missing:
            raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")

    # Best-effort pre-warm of rulepacks and bindings so first request isn't slow.
    try:
        from app.services import rulepacks_engine
        rulepacks_engine.compile_active_rulepacks()
    except Exception:
        pass
    try:
        from app.services.config_store import load_bindings
        load_bindings()
    except Exception:
        pass

    # Initialize decisions store and start prune loop under lifespan
    try:
        from app.services import decisions as decisions_store
        decisions_store.ensure_ready()
    except Exception:
        pass

    prune_task: Optional[asyncio.Task] = None
    try:
        prune_task = asyncio.create_task(_prune_loop())
    except Exception:
        prune_task = None

    await sysmod._startup_readiness()
    try:
        yield
    finally:
        await sysmod._shutdown_readiness()
        # Stop prune loop gracefully
        if prune_task:
            try:
                prune_task.cancel()
                await prune_task
            except Exception:
                pass
        # Clean shutdown for tracer/exporter if present.
        try:
            from opentelemetry import trace as _trace
            provider = _trace.get_tracer_provider()
            shutdown = getattr(provider, "shutdown", None)
            if callable(shutdown):
                shutdown()
        except Exception:
            pass


def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api", lifespan=lifespan)
    try:
        from app.services import decisions as decisions_store

        decisions_store.ensure_ready()
    except Exception:
        pass
    try:
        from app.routes.health import router as health_router

        app.include_router(health_router)
    except Exception:
        pass
    try:
        from app.routes.admin_policy_packs import router as admin_policy_packs_router

        app.include_router(admin_policy_packs_router)
    except Exception:
        pass
    try:
        from app.routes.admin_decisions_api import router as admin_decisions_router

        app.include_router(admin_decisions_router)
    except Exception:
        pass
    try:
        from app.routes.admin_overview import router as admin_overview_router

        app.include_router(admin_overview_router)
    except Exception:
        pass
    app.add_middleware(RequestIDMiddleware)
    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)
    try:
        from app.middleware.rate_limit import RateLimitMiddleware

        app.add_middleware(RateLimitMiddleware)
    except Exception:
        pass
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(EgressRedactMiddleware)
    app.add_middleware(TenantBotMiddleware)

    # Max body size (intercepts early)
    try:
        max_body_mod = __import__("app.middleware.max_body", fromlist=["install_max_body"])
        max_body_mod.install_max_body(app)
    except Exception:
        pass

    app.add_middleware(_LatencyMiddleware)
    app.add_middleware(_NormalizeUnauthorizedMiddleware)
    app.add_middleware(HttpStatusMetricsMiddleware)

    # --- Admin bindings: prefer real router, else fallback ---
    admin_router = None
    try:
        from app.routes import admin as _admin_mod

        admin_router = getattr(_admin_mod, "router", None)
    except Exception:
        try:
            from app.routes.admin.bindings import router as _bindings_router

            admin_router = _bindings_router
        except Exception:
            admin_router = None
    if admin_router is not None:
        app.include_router(admin_router)
    else:
        _install_bindings_fallback(app)

    # --- Explicit admin/policy routers (avoid walker dupes) ---
    try:
        from app.routes import policy_admin

        app.include_router(policy_admin.router)
    except Exception:
        # Intentionally swallow import errors; endpoints just won't be present
        pass

    try:
        from app.routes import (
            admin_config,
            admin_config_history,
            admin_decisions,
            admin_policies,
            admin_rulepacks,
            admin_ui,
            admin_webhook,
            admin_webhook_replay,
            admin_webhooks,
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
    except Exception:
        pass

    # Admin Policy API (version + reload)
    try:
        from app.routes import admin_policy_api

        app.include_router(admin_policy_api.router)
    except Exception:
        # keep startup resilient even if import order changes during refactors
        pass

    # --- Remaining routers (walker skips egress + all admin variants) ---
    _include_all_route_modules(app)

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

        app.add_middleware(DecisionHeaderMiddleware)
    except Exception:
        pass
    install_json_logging(app)

    # NOTE: startup event hook intentionally removed; custom lifespan handles prune loop.

    return app


build_app = create_app
app = create_app()

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

try:
    from starlette.middleware.gzip import GZipMiddleware as _StarletteGZip
    if _truthy(os.getenv("COMPRESSION_ENABLED", "0")):
        app.add_middleware(
            _StarletteGZip,
            minimum_size=_parse_int_env("COMPRESSION_MIN_SIZE_BYTES", 0),
        )
except Exception:
    pass
