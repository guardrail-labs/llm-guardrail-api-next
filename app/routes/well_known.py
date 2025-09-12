# app/routes/well_known.py
# Summary (PR-S): Adds /robots.txt and /.well-known/security.txt.
# - /robots.txt: disallow /admin by default; override via ROBOTS_ALLOW/ROBOTS_DISALLOW.
# - /.well-known/security.txt: served only if SECURITY_CONTACT is set; see https://securitytxt.org/
# - Auto-included by main.py's dynamic route loader; no wiring changes.

from __future__ import annotations

import os
from typing import List

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

router = APIRouter()


def _env_list(name: str) -> List[str]:
    raw = os.getenv(name, "") or ""
    # split on commas; trim; drop empties
    return [p.strip() for p in raw.split(",") if p.strip()]


@router.get("/robots.txt")
def robots_txt() -> Response:
    """
    Minimal robots.txt. Defaults to disallow /admin; override with ROBOTS_ALLOW
    and ROBOTS_DISALLOW (comma-separated absolute paths).
    """
    allows = _env_list("ROBOTS_ALLOW")
    disallows = _env_list("ROBOTS_DISALLOW") or ["/admin"]

    lines: List[str] = ["User-agent: *"]
    for p in allows:
        lines.append(f"Allow: {p}")
    for p in disallows:
        lines.append(f"Disallow: {p}")

    body = "\n".join(lines) + "\n"
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8")


@router.get("/.well-known/security.txt")
def security_txt() -> Response:
    """
    security.txt per RFC draft. Only served if SECURITY_CONTACT is set.
    Optional:
      - SECURITY_POLICY
      - SECURITY_ENCRYPTION
      - SECURITY_ACKNOWLEDGEMENTS
      - SECURITY_PREFERRED_LANG (e.g., "en, fr")
    """
    contact = os.getenv("SECURITY_CONTACT", "").strip()
    if not contact:
        # Don’t publish an empty file; 404 keeps behavior minimal by default.
        return Response(status_code=404)

    lines: List[str] = [f"Contact: {contact}"]

    policy = os.getenv("SECURITY_POLICY", "").strip()
    if policy:
        lines.append(f"Policy: {policy}")

    encryption = os.getenv("SECURITY_ENCRYPTION", "").strip()
    if encryption:
        lines.append(f"Encryption: {encryption}")

    ack = os.getenv("SECURITY_ACKNOWLEDGEMENTS", "").strip()
    if ack:
        lines.append(f"Acknowledgements: {ack}")

    langs = os.getenv("SECURITY_PREFERRED_LANG", "").strip()
    if langs:
        lines.append(f"Preferred-Languages: {langs}")

    # Optional caching: short TTL to allow quick edits if misconfigured.
    body = "\n".join(lines) + "\n"
    return PlainTextResponse(
        body,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=600"},
    )

