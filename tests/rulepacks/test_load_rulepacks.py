from app.services.rulepacks import list_rulepacks, load_rulepack


def test_rulepack_scaffolds_load():
    rp = list_rulepacks()
    assert "hipaa" in rp and "gdpr" in rp

    hipaa = load_rulepack("hipaa")
    gdpr = load_rulepack("gdpr")
    assert hipaa.get("name") == "HIPAA"
    assert gdpr.get("name") == "GDPR"
