from __future__ import annotations

from app.services.trace.validate import validate_trace_payload


def test_trace_validator_accepts_good_shape():
    ok, errs = validate_trace_payload({
        "action": "allow",
        "text": "hello",
        "rule_hits": [],
        "redactions": {"secrets": 0},
        "trace": ["ingress", "sanitizers", "llm", "egress"],
        "debug": {"sources": []},
        "incident_id": "gr-123",
    })
    assert ok is True and errs == []


def test_trace_validator_flags_missing_and_types():
    ok, errs = validate_trace_payload({
        "action": "block",
        "text": "nope",
        "rule_hits": "not a list",
        "debug": [],
    })
    assert ok is False
    assert "rule_hits:not_list" in errs
    # missing redactions/trace are fine; but debug type is wrong
    assert "debug:not_dict" in errs
