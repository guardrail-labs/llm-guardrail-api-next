from __future__ import annotations

import os
import secrets
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class AdminSessionMiddleware(BaseHTTPMiddleware):
    """Ensure admin session + CSRF cookies for /admin routes."""

    def __init__(self, app):
        super().__init__(app)
        self._session_cookie = (
            os.getenv("ADMIN_SESSION_COOKIE") or "admin_sess"
        ).strip() or "admin_sess"
        self._csrf_cookie = (os.getenv("ADMIN_CSRF_COOKIE") or "admin_csrf").strip() or "admin_csrf"
        path = (os.getenv("ADMIN_COOKIE_PATH") or "/admin").strip() or "/admin"
        if not path.startswith("/"):
            path = f"/{path}"
        self._cookie_path = path
        self._ttl = self._parse_ttl(os.getenv("ADMIN_SESSION_TTL_SECONDS"))
        self._secure = self._parse_secure_flag(os.getenv("ADMIN_COOKIE_SECURE"))
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()

    @staticmethod
    def _parse_ttl(raw: Optional[str]) -> int:
        raw_value = (raw or "").strip()
        default = 1800
        if not raw_value:
            return default
        try:
            parsed = int(raw_value)
        except Exception:
            return default

        minimum = 300
        maximum = 86400
        if parsed < minimum:
            return minimum
        if parsed > maximum:
            return maximum
        return parsed

    @staticmethod
    def _parse_secure_flag(raw: Optional[str]) -> bool:
        raw_value = (raw or "").strip().lower()
        if not raw_value:
            return True
        if raw_value in {"0", "false", "off", "no"}:
            return False
        if raw_value in {"1", "true", "on", "yes"}:
            return True
        return True

    def _is_admin_path(self, path: str) -> bool:
        base = self._cookie_path.rstrip("/") or "/"
        if base == "/":
            return True
        if path == base:
            return True
        return path.startswith(f"{base}/")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path if request.url else ""
        is_admin_path = self._is_admin_path(path)
        session_value: Optional[str] = None
        store: Optional[Dict[str, Any]] = None
        new_session = False
        if is_admin_path:
            req_session = request.cookies.get(self._session_cookie)
            new_session = not bool(req_session)
            session_value = req_session or secrets.token_urlsafe(32)
            with self._lock:
                store = self._sessions.setdefault(session_value, {})
            request.scope["session"] = store

        response = await call_next(request)

        if not is_admin_path:
            return response

        def _response_has_cookie(resp: Response, name: str) -> bool:
            try:
                raw_headers = getattr(resp, "raw_headers", None) or []
                for k, v in raw_headers:
                    if k.lower() != b"set-cookie":
                        continue
                    try:
                        serialized = v.decode("latin-1", errors="ignore")
                    except Exception:
                        continue
                    if serialized.lstrip().startswith(f"{name}="):
                        return True
            except Exception:
                pass
            return False

        req_csrf = request.cookies.get(self._csrf_cookie)
        resp_sets_session = _response_has_cookie(response, self._session_cookie)
        resp_sets_csrf = _response_has_cookie(response, self._csrf_cookie)
        if session_value is None:
            session_value = secrets.token_urlsafe(32)
            with self._lock:
                store = self._sessions.setdefault(session_value, {})

        csrf_value: Optional[str] = None
        should_set_csrf = False
        if not resp_sets_csrf:
            if new_session:
                csrf_value = secrets.token_urlsafe(32)
                should_set_csrf = True
            elif req_csrf:
                csrf_value = req_csrf
                should_set_csrf = True
            else:
                csrf_value = secrets.token_urlsafe(32)
                should_set_csrf = True

        max_age = self._ttl

        if not resp_sets_session and session_value:
            response.set_cookie(
                key=self._session_cookie,
                value=session_value,
                max_age=max_age,
                path=self._cookie_path,
                secure=self._secure,
                httponly=True,
                samesite="strict",
            )

        if should_set_csrf and csrf_value:
            response.set_cookie(
                key=self._csrf_cookie,
                value=csrf_value,
                max_age=max_age,
                path=self._cookie_path,
                secure=self._secure,
                httponly=False,
                samesite="strict",
            )

        scope_session = request.scope.get("session")
        if isinstance(scope_session, dict) and session_value:
            with self._lock:
                if store is not None and scope_session is not store:
                    self._sessions[session_value] = dict(scope_session)
                    store = self._sessions[session_value]
                if not scope_session:
                    self._sessions.pop(session_value, None)
        elif session_value:
            with self._lock:
                self._sessions.pop(session_value, None)

        return response
