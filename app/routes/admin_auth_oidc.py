from __future__ import annotations

import secrets
import urllib.parse
from typing import Any, Callable, Dict, Optional, cast

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from app import config
from app.security import oidc as oidc_helpers

UiCsrfChecker = Callable[[Request, str], None]
try:  # pragma: no cover - admin UI optional in some deployments
    from app.routes.admin_ui import _require_ui_csrf as _ui_csrf_impl
except Exception:  # pragma: no cover - admin UI not available
    _ui_csrf_impl = None  # type: ignore[assignment]

_ui_csrf_check: Optional[UiCsrfChecker] = cast(Optional[UiCsrfChecker], _ui_csrf_impl)


router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


def _base_url(request: Request) -> str:
    url = str(request.base_url).rstrip("/")
    return url or ""


def _ensure_enabled() -> None:
    if not config.OIDC_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if not (config.OIDC_CLIENT_ID and config.OIDC_ISSUER):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC not configured",
        )


@router.get("/login")
async def login(request: Request) -> Response:
    _ensure_enabled()
    try:
        openid = await oidc_helpers.fetch_openid_config()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}") from exc

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce

    params = {
        "client_id": config.OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _base_url(request) + config.OIDC_REDIRECT_PATH,
        "scope": config.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    location = openid["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(location)


async def _exchange_code(code: str, request: Request, token_endpoint: str) -> Dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _base_url(request) + config.OIDC_REDIRECT_PATH,
        "client_id": config.OIDC_CLIENT_ID,
    }
    if config.OIDC_CLIENT_SECRET:
        payload["client_secret"] = config.OIDC_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=5) as client:
        try:
            response = await client.post(token_endpoint, data=payload)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"OIDC token exchange failed: {exc}",
            ) from exc
    data = response.json()
    if not isinstance(data, dict):  # pragma: no cover - unexpected payload
        raise HTTPException(status_code=502, detail="Invalid token response")
    return cast(Dict[str, Any], data)


@router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None) -> Response:
    _ensure_enabled()

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    session_state = request.session.get("oidc_state")
    if not session_state or state != session_state:
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        openid = await oidc_helpers.fetch_openid_config()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}") from exc

    token_endpoint = openid.get("token_endpoint")
    if not token_endpoint:
        raise HTTPException(status_code=502, detail="Token endpoint unavailable")

    token_payload = await _exchange_code(code, request, token_endpoint)
    id_token = token_payload.get("id_token")
    if not isinstance(id_token, str):
        raise HTTPException(status_code=400, detail="Missing id_token in response")

    try:
        jwks = await oidc_helpers.fetch_jwks(openid["jwks_uri"])
        claims = oidc_helpers.verify_id_token(id_token, jwks)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"ID token verification failed: {exc}") from exc

    expected_nonce = request.session.get("oidc_nonce")
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    email = str(claims.get(config.OIDC_EMAIL_CLAIM) or "")
    name = str(claims.get(config.OIDC_NAME_CLAIM) or email or "User")
    role = oidc_helpers.map_role(claims)

    request.session["user"] = {
        "email": email,
        "name": name,
        "role": role,
        "oidc": True,
    }
    request.session.pop("oidc_state", None)
    request.session.pop("oidc_nonce", None)

    return RedirectResponse("/admin/")


async def _extract_csrf_token(request: Request) -> str:
    try:
        form = await request.form()
    except Exception:
        form = None
    token = None
    if form is not None:
        token = form.get("csrf_token")
    token = token or request.headers.get("X-CSRF-Token")
    return str(token or "")


@router.post("/logout")
async def logout(request: Request) -> Response:
    token = await _extract_csrf_token(request)
    if _ui_csrf_check is not None:
        if token or request.cookies.get("ui_csrf"):
            _ui_csrf_check(request, token)

    request.session.clear()

    if config.OIDC_LOGOUT_URL:
        return RedirectResponse(config.OIDC_LOGOUT_URL)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
