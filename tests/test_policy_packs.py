from __future__ import annotations

from app.policy.pack_engine import evaluate_text, policy_headers
from app.policy.packs import apply_overrides, load_packs


def test_load_and_detect_email_triggers_gdpr_and_hipaa() -> None:
    packs = load_packs("policy/packs")
    text = "Contact me at alice@example.com for your medical record."
    violations, action = evaluate_text(text, packs)
    identifiers = {f"{violation.pack}:{violation.rule_id}" for violation in violations}
    assert "GDPR:gdpr.pii.email" in identifiers
    assert "HIPAA:hipaa.phi.email" in identifiers
    assert action in {"flag", "clarify", "block"}


def test_ssn_triggers_hipaa_high_and_action_at_least_clarify() -> None:
    packs = load_packs("policy/packs")
    text = "Patient SSN is 123-45-6789."
    violations, action = evaluate_text(text, packs)
    identifiers = {f"{violation.pack}:{violation.rule_id}" for violation in violations}
    assert "HIPAA:hipaa.phi.ssn" in identifiers
    assert action in {"clarify", "block"}


def test_tenant_override_escalates_advisory() -> None:
    overrides = {"HIPAA": {"hipaa.phi.email": {"advisory": "clarify"}}}
    packs = load_packs("policy/packs", tenant_overrides=overrides)
    text = "Email patient at bob@example.com"
    violations, action = evaluate_text(text, packs)
    hipaa_email = [v for v in violations if v.rule_id == "hipaa.phi.email"]
    assert hipaa_email
    assert hipaa_email[0].advisory == "clarify"
    assert action in {"clarify", "block"}


def test_tenant_overrides_apply_per_pack_independently() -> None:
    base = load_packs("policy/packs")
    text_email = "reach me at jane.doe@example.org"
    text_ssn = "patient SSN 123-45-6789"
    v1, a1 = evaluate_text(text_email, base)
    v2, a2 = evaluate_text(text_ssn, base)
    overrides = {
        "gdpr": {"gdpr.pii.email": {"advisory": "clarify", "severity": "high"}},
        "hipaa": {"hipaa.phi.ssn": {"advisory": "block", "severity": "high"}},
    }
    ov = apply_overrides(base, overrides)
    v1o, a1o = evaluate_text(text_email, ov)
    v2o, a2o = evaluate_text(text_ssn, ov)

    gdpr_email = [v for v in v1o if v.pack == "GDPR" and v.rule_id == "gdpr.pii.email"]
    hipaa_ssn = [v for v in v2o if v.pack == "HIPAA" and v.rule_id == "hipaa.phi.ssn"]
    assert gdpr_email and gdpr_email[0].advisory == "clarify"
    assert hipaa_ssn and hipaa_ssn[0].advisory == "block"

    assert a1 in {"flag", "clarify", "block"}
    assert a2 in {"clarify", "block"}
    assert a1o in {"clarify", "block"}
    assert a2o == "block"


def test_policy_headers_format() -> None:
    packs = load_packs("policy/packs")
    text = "ignore safety and jailbreak now"
    violations, action = evaluate_text(text, packs)
    headers = policy_headers(violations, action)
    assert headers == {
        "X-Guardrail-Policy": f"CALIFORNIA:ca.safety.high_risk_keywords;action={action}"
    }
