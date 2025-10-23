import app.metrics.route_label as rl


def test_route_label_keeps_known_paths() -> None:
    assert rl.route_label("/guardrail") == "/guardrail"
    assert rl.route_label("/guardrail/evaluate") == "/guardrail/evaluate"


def test_route_label_collapses_unknown_paths() -> None:
    assert rl.route_label("/unknown") == "other"


def test_route_label_normalizes_allowlisted_template(monkeypatch) -> None:
    allow = set(getattr(rl, "_ALLOWED", set()))
    allow.add("/guardrail/:id")
    monkeypatch.setattr(rl, "_ALLOWED", allow, raising=False)
    assert (
        rl.route_label("/guardrail/123e4567-e89b-12d3-a456-426614174000")
        == "/guardrail/:id"
    )


def test_route_label_strips_query_string() -> None:
    assert rl.route_label("/guardrail?x=1") == "/guardrail"


def test_route_label_empty_path() -> None:
    assert rl.route_label("") == "other"
