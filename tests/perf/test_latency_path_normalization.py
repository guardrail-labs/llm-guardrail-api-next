from __future__ import annotations

import app.metrics.route_label as rl
from app.middleware.latency_instrument import _route_label


def test_route_label_normalizes_ids_and_long_segments(monkeypatch) -> None:
    allow = set(getattr(rl, "_ALLOWED", set()))
    allow.update({"/admin/decisions/:id/details", "/files/:id/info", "/x/:seg/y"})
    monkeypatch.setattr(rl, "_ALLOWED", allow, raising=False)
    # UUID → :id
    p1 = "/admin/decisions/123e4567-e89b-12d3-a456-426614174000/details"
    # ULID-like → :id
    p2 = "/admin/decisions/01HZY1J0K8Q9M8TNJ9A4V8XK5C/details"
    # long hex → :id
    p3 = "/files/abcdef0123456789abcdef0123456789/info"
    # long segment → :seg
    p4 = "/x/" + "a" * 40 + "/y"

    l1 = _route_label(p1)
    l2 = _route_label(p2)
    l3 = _route_label(p3)
    l4 = _route_label(p4)

    assert l1 == "/admin/decisions/:id/details"
    assert l2 == "/admin/decisions/:id/details"
    assert l3 == "/files/:id/info"
    assert l4 == "/x/:seg/y"


def test_route_label_keeps_static_paths(monkeypatch) -> None:
    allow = set(getattr(rl, "_ALLOWED", set()))
    allow.update({"/", "/healthz", "/admin/ui/purge"})
    monkeypatch.setattr(rl, "_ALLOWED", allow, raising=False)
    assert _route_label("/") == "/"
    assert _route_label("/healthz") == "/healthz"
    assert _route_label("/admin/ui/purge") == "/admin/ui/purge"
