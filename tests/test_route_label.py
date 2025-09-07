from app.metrics.route_label import route_label


def test_route_label_allows_known_paths():
    assert route_label("/guardrail") == "/guardrail"
    assert route_label("/guardrail/evaluate") == "/guardrail/evaluate"


def test_route_label_unknown_maps_to_other():
    assert route_label("/unknown") == "other"


def test_route_label_strips_query_string():
    assert route_label("/guardrail?x=1") == "/guardrail"


def test_route_label_empty_path():
    assert route_label("") == "other"
