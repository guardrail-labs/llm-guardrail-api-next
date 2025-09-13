from app.services.rulepacks_engine import (
    compile_active_rulepacks,
    ingress_should_block,
    rulepacks_enabled,
)


def test_compile_active_rulepacks(monkeypatch):
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "hipaa,gdpr")
    assert rulepacks_enabled()
    rp = compile_active_rulepacks(force=True)
    assert len(rp.egress_redactions) >= 2
    assert any("DROP" in p.pattern.upper() for p in rp.ingress_block_regexes)


def test_ingress_should_block(monkeypatch):
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "gdpr")
    should, hits = ingress_should_block("please DROP TABLE users;")
    assert should is True
    assert hits
