# app/main.py
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
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


_PRUNE_INTERVAL_SECONDS = _parse_int_env("DECISIONS_PRUNE_INTERVAL_SECONDS", 3600)


async def _prune_loop() -> None:
    interval = max(_PRUNE_INTERVAL_SECONDS, 1)
    while True:
        try:
            from app.services import decisions as decisions_store

            decisions_store.prune()
        except Exception:
            pass
        try:
            await asyncio.sleep(interval)
        except Exception:
            return


def _start_prune_task(app: FastAPI) -> None:
    """
    Start the prune loop once. Safe to call from both lifespan and startup.
    """
    try:
        if getattr(app.state, "prune_task", None):
            return
        task = asyncio.create_task(_prune_loop())
        app.state.prune_task = task
    except Exception:
        pass


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
            "rules_path"_
