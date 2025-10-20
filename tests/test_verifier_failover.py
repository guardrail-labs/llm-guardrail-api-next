from __future__ import annotations

from app.verifier.base import VerifyInput
from app.verifier.manager import VerifierManager
from app.verifier.providers.dummy import DummyVerifier


def test_single_healthy_provider_allows() -> None:
    vm = VerifierManager([DummyVerifier(name="p1", healthy=True)])
    res, hdr, prov = vm.verify_with_failover(VerifyInput(text="hello"))
    assert res.allowed is True
    assert hdr["X-Guardrail-Decision"] == "allow"
    assert prov == "p1"


def test_policy_block_from_provider() -> None:
    vm = VerifierManager([DummyVerifier(name="p1", healthy=True)])
    res, hdr, prov = vm.verify_with_failover(VerifyInput(text="BLOCKME"))
    assert res.allowed is False
    assert hdr["X-Guardrail-Decision"] == "block-input"
    assert prov == "p1"


def test_failover_on_error_then_success() -> None:
    bad = DummyVerifier(name="bad", healthy=True, fail=True)
    good = DummyVerifier(name="good", healthy=True)
    vm = VerifierManager([bad, good])
    res, hdr, prov = vm.verify_with_failover(VerifyInput(text="hi"))
    assert res.allowed is True
    assert prov == "good"


def test_timeouts_mark_unhealthy_and_failover() -> None:
    slow = DummyVerifier(name="slow", healthy=True, sleep_s=10.0)
    fast = DummyVerifier(name="fast", healthy=True, sleep_s=0.0)
    vm = VerifierManager([slow, fast])
    res, hdr, prov = vm.verify_with_failover(VerifyInput(text="hi"), timeout_s=0.01)
    assert res.allowed is True
    assert prov == "fast"


def test_total_outage_default_blocks_with_incident() -> None:
    bad = DummyVerifier(name="bad", healthy=False, fail=True)
    vm = VerifierManager([bad])
    res, hdr, prov = vm.verify_with_failover(VerifyInput(text="hi"))
    assert res.allowed is False
    assert prov in {"failover", "none"}
    assert hdr["X-Guardrail-Decision"] == "block-input"
    assert "X-Guardrail-Incident-ID" in hdr
