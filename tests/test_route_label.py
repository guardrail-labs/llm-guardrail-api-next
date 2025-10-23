from app.metrics.route_label import route_label


def test_route_label_keeps_known_paths() -> None:
    assert route_label("/guardrail") == "/guardrail"
    assert route_label("/guardrail/evaluate") == "/guardrail/evaluate"


def test_route_label_normalizes_unknown_paths() -> None:
    assert route_label("/unknown") == "/unknown"
    assert (
        route_label("/guardrail/123e4567-e89b-12d3-a456-426614174000")
        == "/guardrail/:id"
    )


def test_route_label_strips_query_string() -> None:
    assert route_label("/guardrail?x=1") == "/guardrail"


def test_route_label_empty_path() -> None:
    assert route_label("") == "other"
