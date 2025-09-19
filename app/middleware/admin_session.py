from __future__ import annotations

import os
import secrets
from typing import Awaitable, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class AdminSessionMiddleware(BaseHTTPMiddleware):
    """Ensure admin session + CSRF cookies for /admin routes."""

    def __init__(self, app):
        super().__init__(app)
        self._session_cookie = (
            (os.getenv("ADMIN_SESSION_COOKIE") or "admin_sess").strip() or "admin_sess"
        )
        self._csrf_cookie = (
            (os.getenv("ADMIN_CSRF_COOKIE") or "admin_csrf").strip() or "admin_csrf"
        )
        path = (os.getenv("ADMIN_COOKIE_PATH") or "/admin").strip() or "/admin"
        if not path.startswith("/"):
            path = f"/{path}"
        self._cookie_path = path
        self._ttl = self._parse_ttl(os.getenv("ADMIN_SESSION_TTL_SECONDS"))
        self._secure = self._secure_cookies_enabled()

    @staticmethod
    def _parse_ttl(raw: Optional[str]) -> Optional[int]:
        raw = (raw or "").strip()
        if not raw:
            return 1800
        try:
            value = int(raw)
        except Exception:
            return 1800
        return value if value > 0 else None

    @staticmethod
    def _secure_cookies_enabled() -> bool:
        raw = (os.getenv("ADMIN_SECURE_COOKIES") or "").strip().lower()
        return raw not in {"0", "false", "off", "no"}

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
        response = await call_next(request)
        path = request.url.path if request.url else ""
        if not self._is_admin_path(path):
            return response

        session_value = request.cookies.get(self._session_cookie)
        csrf_value = request.cookies.get(self._csrf_cookie)

        if not session_value:
            session_value = secrets.token_urlsafe(32)
            csrf_value = secrets.token_urlsafe(32)
        elif not csrf_value:
            csrf_value = secrets.token_urlsafe(32)

        max_age = self._ttl
        response.set_cookie(
            key=self._session_cookie,
            value=session_value,
            max_age=max_age,
            path=self._cookie_path,
            secure=self._secure,
            httponly=True,
            samesite="strict",
        )
        if csrf_value:
            response.set_cookie(
                key=self._csrf_cookie,
                value=csrf_value,
                max_age=max_age,
                path=self._cookie_path,
                secure=self._secure,
                httponly=False,
                samesite="strict",
            )
        return response
