import pytest

from app.security.rbac import RBACError, _value_in_scope, ensure_scope


class U:
    def __init__(self, tenants, bots):
        self.scope = {"tenants": tenants, "bots": bots}


def test_value_in_scope_star_allows_none():
    assert _value_in_scope("*", None) is True


def test_value_in_scope_nonstar_rejects_none():
    assert _value_in_scope("acme", None) is False
    assert _value_in_scope(["acme", "beta"], None) is False


def test_value_in_scope_membership_and_exact():
    assert _value_in_scope("acme", "acme") is True
    assert _value_in_scope(["acme", "beta"], "acme") is True
    assert _value_in_scope(["acme", "beta"], "other") is False


def test_ensure_scope_requires_filters_for_scoped_tokens():
    user = U(tenants=["acme"], bots=["site"])
    with pytest.raises(RBACError):
        ensure_scope(user, tenant=None, bot="site")
    with pytest.raises(RBACError):
        ensure_scope(user, tenant="acme", bot=None)


def test_ensure_scope_allows_when_filters_match():
    user = U(tenants=["acme"], bots=["site"])
    ensure_scope(user, tenant="acme", bot="site")


def test_ensure_scope_star_permits_missing_filters():
    user = U(tenants="*", bots="*")
    ensure_scope(user, tenant=None, bot=None)


def test_ensure_scope_rejects_out_of_scope_values():
    user = U(tenants=["acme"], bots=["site"])
    with pytest.raises(RBACError):
        ensure_scope(user, tenant="other", bot="site")
    with pytest.raises(RBACError):
        ensure_scope(user, tenant="acme", bot="other")
