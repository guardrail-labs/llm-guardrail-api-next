from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapped(message):
            if message.get("type") == "http.response.start":
                headers = message.setdefault("headers", [])

                def set_header(key: str, value: str) -> None:
                    headers.append((key.encode("latin-1"), value.encode("latin-1")))

                s = get_settings()
                if s.SECURITY_HEADERS_ENABLED:
                    set_header("X-Content-Type-Options", "nosniff")
                    set_header("X-Frame-Options", "DENY")
                    set_header("X-XSS-Protection", "0")
                    set_header("Referrer-Policy", "no-referrer")
                    if s.ADD_PERMISSIONS_POLICY:
                        set_header("Permissions-Policy", "interest-cohort=()")
                    if s.ADD_COOP:
                        set_header("Cross-Origin-Opener-Policy", "same-origin")
                    if s.ADD_HSTS:
                        # Always-on for simplicity; for strict setups you can gate
                        # by X-Forwarded-Proto = https if desired.
                        max_age = str(int(s.HSTS_MAX_AGE))
                        set_header(
                            "Strict-Transport-Security",
                            f"max-age={max_age}; includeSubDomains",
                        )
            await send(message)

        await self.app(scope, receive, send_wrapped)
