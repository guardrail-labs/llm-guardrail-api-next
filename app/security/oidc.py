from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app import config

router = APIRouter(prefix="/auth", tags=["auth"])

try:  # pragma: no cover - optional dependency
    from authlib.integrations.starlette_client import OAuth

    _HAVE_AUTHLIB = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_AUTHLIB = False

if _HAVE_AUTHLIB and config.ADMIN_AUTH_MODE == "oidc":
    oauth = OAuth()
    oauth.register(
        name="oidc",
        server_metadata_url=f"{config.OIDC_ISSUER}/.well-known/openid-configuration",
        client_id=config.OIDC_CLIENT_ID,
        client_secret=config.OIDC_CLIENT_SECRET,
        client_kwargs={"scope": config.OIDC_SCOPES},
    )

    @router.get("/login")
    async def login(request: Request):
        redirect_uri = config.OIDC_REDIRECT_URI or str(request.url_for("auth_callback"))
        return await oauth.oidc.authorize_redirect(request, redirect_uri)

    @router.get("/callback")
    async def auth_callback(request: Request):
        token = await oauth.oidc.authorize_access_token(request)
        userinfo = token.get("userinfo") or {}
        request.session["user"] = {
            "email": userinfo.get("email") or "",
            "name": userinfo.get("name") or "",
            "roles": userinfo.get("roles") or [],
        }
        return Response(status_code=302, headers={"Location": "/admin/"})
else:

    @router.get("/login")
    async def login_disabled():
        return Response("OIDC disabled", status_code=501)

    @router.get("/callback")
    async def callback_disabled():
        return Response("OIDC disabled", status_code=501)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return Response(status_code=204)
