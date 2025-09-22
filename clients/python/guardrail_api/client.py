"""Thin synchronous client for the Guardrail API."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple, Union, cast

import httpx

from .models import AdjudicationPage, DecisionPage

Scope = Optional[Union[str, Iterable[str]]]


class GuardrailClient:
    """Lightweight helper for interacting with the Guardrail API."""

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.timeout = timeout

    def _get(self, path: str, params: Dict[str, Any] | None = None) -> httpx.Response:
        with httpx.Client(timeout=self.timeout, headers=self.headers) as client:
            response = client.get(f"{self.base_url}{path}", params=params)
            response.raise_for_status()
            return response

    # Health -----------------------------------------------------------------
    def healthz(self) -> Dict[str, Any]:
        """Return the /healthz payload."""

        return cast(Dict[str, Any], self._get("/healthz").json())

    def readyz(self) -> Dict[str, Any]:
        """Return the /readyz payload."""

        return cast(Dict[str, Any], self._get("/readyz").json())

    # Decisions ---------------------------------------------------------------
    def list_decisions(
        self,
        *,
        tenant: Scope = None,
        bot: Scope = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        dir: str = "fwd",
        **filters: Any,
    ) -> DecisionPage:
        """List decisions with cursor pagination."""

        params: Dict[str, Any] = {"limit": limit, "dir": dir, **filters}
        if cursor:
            params["cursor"] = cursor
        if tenant is not None:
            params["tenant"] = _normalize_scope(tenant)
        if bot is not None:
            params["bot"] = _normalize_scope(bot)
        return cast(DecisionPage, self._get("/admin/api/decisions", params=params).json())

    def export_decisions(self, *, tenant: Optional[str] = None, bot: Optional[str] = None) -> str:
        """Export decisions as an NDJSON stream (returned as text)."""

        params: Dict[str, Any] = {}
        if tenant is not None:
            params["tenant"] = tenant
        if bot is not None:
            params["bot"] = bot
        # Server expects /admin/api/decisions/export with format selector.
        params["format"] = "jsonl"
        response = self._get("/admin/api/decisions/export", params=params)
        return response.text

    # Adjudications ----------------------------------------------------------
    def list_adjudications(
        self,
        *,
        tenant: Scope = None,
        bot: Scope = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        dir: str = "fwd",
        **filters: Any,
    ) -> AdjudicationPage:
        """List adjudications with cursor pagination."""

        params: Dict[str, Any] = {"limit": limit, "dir": dir, **filters}
        if cursor:
            params["cursor"] = cursor
        if tenant is not None:
            params["tenant"] = _normalize_scope(tenant)
        if bot is not None:
            params["bot"] = _normalize_scope(bot)
        return cast(
            AdjudicationPage,
            self._get("/admin/api/adjudications", params=params).json(),
        )

    def export_adjudications(
        self,
        *,
        tenant: Optional[str] = None,
        bot: Optional[str] = None,
    ) -> str:
        """Export adjudications as an NDJSON stream (returned as text)."""

        params: Dict[str, Any] = {}
        if tenant is not None:
            params["tenant"] = tenant
        if bot is not None:
            params["bot"] = bot
        # Server exposes NDJSON at /admin/api/adjudications/export.ndjson
        response = self._get("/admin/api/adjudications/export.ndjson", params=params)
        return response.text


def _normalize_scope(scope: Scope) -> Union[str, Tuple[str, ...]]:
    if scope is None:
        return ()
    if isinstance(scope, str):
        return scope
    return tuple(str(item) for item in scope)


__all__ = ["GuardrailClient", "Scope"]
