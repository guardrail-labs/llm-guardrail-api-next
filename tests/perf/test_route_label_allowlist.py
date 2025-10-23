from __future__ import annotations

import app.metrics.route_label as rl


def test_unknown_paths_collapse_to_other():
    # Ensure a random slug is not emitted as a label
    assert rl.route_label("/foo/randomslug") == "other"
    assert rl.route_label("/foo/bar?x=1") == "other"
    assert rl.route_label("") == "other"


def test_allowlisted_static_passes_through(monkeypatch):
    # Temporarily extend allowlist for test
    allow = set(getattr(rl, "_ALLOWED", set()))
    allow.add("/healthz")
    monkeypatch.setattr(rl, "_ALLOWED", allow, raising=False)
    assert rl.route_label("/healthz") == "/healthz"


def test_allowlisted_templates_work(monkeypatch):
    # Allow a normalized template and confirm normalization then allowlist match
    allow = set(getattr(rl, "_ALLOWED", set()))
    allow.add("/admin/decisions/:id/details")
    monkeypatch.setattr(rl, "_ALLOWED", allow, raising=False)

    uuid_path = "/admin/decisions/123e4567-e89b-12d3-a456-426614174000/details"
    ulid_path = "/admin/decisions/01HZY1J0K8Q9M8TNJ9A4V8XK5C/details"
    num_path = "/admin/decisions/123456/details"

    assert rl.route_label(uuid_path) == "/admin/decisions/:id/details"
    assert rl.route_label(ulid_path) == "/admin/decisions/:id/details"
    assert rl.route_label(num_path) == "/admin/decisions/:id/details"
