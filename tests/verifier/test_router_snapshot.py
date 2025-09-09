from app.services.verifier.provider_router import ProviderRouter


def test_get_last_order_snapshot_returns_expected_structure() -> None:
    router = ProviderRouter()
    providers = ["a", "b"]
    router.rank("t1", "b1", providers)
    snap = router.get_last_order_snapshot()
    assert isinstance(snap, list)
    assert any(
        isinstance(entry, dict)
        and entry.get("tenant") == "t1"
        and entry.get("bot") == "b1"
        and isinstance(entry.get("order"), list)
        and isinstance(entry.get("last_ranked_at"), float)
        for entry in snap
    )
