from __future__ import annotations

from app.services.bindings.models import Binding
from app.services.bindings.validator import (
    BindingIssue,
    choose_binding_for,
    validate_bindings,
)


def _kinds(issues: list[BindingIssue]) -> set[str]:
    return {i.kind for i in issues}


def test_duplicate_same_target_same_outcome_warning() -> None:
    a = Binding(tenant_id="t1", bot_id="b1", policy_version="pA", priority=1)
    b = Binding(tenant_id="t1", bot_id="b1", policy_version="pA", priority=2)
    issues = validate_bindings([a, b])
    assert "duplicate" in _kinds(issues)
    assert any(i.severity == "warning" for i in issues if i.kind == "duplicate")


def test_incompatible_same_target_error() -> None:
    a = Binding(tenant_id="t1", bot_id="b1", policy_version="pA")
    b = Binding(tenant_id="t1", bot_id="b1", policy_version="pB")
    issues = validate_bindings([a, b])
    assert "incompatible" in _kinds(issues)
    assert any(i.severity == "error" for i in issues if i.kind == "incompatible")


def test_overlap_equal_priority_warning() -> None:
    a = Binding(tenant_id="*", bot_id="b1", policy_version="pA", priority=10)
    b = Binding(tenant_id="t1", bot_id="*", policy_version="pB", priority=10)
    issues = validate_bindings([a, b])
    assert "overlap" in _kinds(issues)
    assert any(i.severity == "warning" for i in issues if i.kind == "overlap")


def test_shadowed_lower_priority_info() -> None:
    a = Binding(tenant_id="*", bot_id="b1", policy_version="pA", priority=1)
    b = Binding(tenant_id="t1", bot_id="b1", policy_version="pB", priority=5)
    issues = validate_bindings([a, b])
    assert "shadowed" in _kinds(issues)
    assert any(i.severity == "info" for i in issues if i.kind == "shadowed")


def test_empty_policy_is_error() -> None:
    a = Binding(tenant_id="t1", bot_id="b1", policy_version="")
    issues = validate_bindings([a])
    assert any(i.kind == "invalid" and i.severity == "error" for i in issues)


def test_choose_binding_prefers_higher_priority_then_specificity() -> None:
    # Three candidates: wildcard-low, wildcard-high, and specific-medium priority
    b1 = Binding(tenant_id="*", bot_id="b1", policy_version="p1", priority=1)
    b2 = Binding(tenant_id="t1", bot_id="*", policy_version="p2", priority=3)
    b3 = Binding(tenant_id="t1", bot_id="b1", policy_version="p3", priority=2)
    selected, candidates = choose_binding_for([b1, b2, b3], "t1", "b1")
    assert selected is b2  # highest priority wins even if less specific
    assert len(candidates) == 3

