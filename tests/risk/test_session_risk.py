from app.risk.session_risk import session_risk_store


def test_risk_bump_and_decay():
    store = session_risk_store()
    tenant, bot, sess = "t", "b", "s"
    s1 = store.bump(tenant, bot, sess, 1.5, ttl_seconds=60)
    assert s1 >= 1.5
    s2 = store.decay_and_get(tenant, bot, sess, half_life_seconds=0)  # no decay
    assert abs(s2 - s1) < 1e-6
