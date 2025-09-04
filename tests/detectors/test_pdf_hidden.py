from app.services.detectors import pdf_sanitize_for_downstream
from app.services.detectors.ingress_pipeline import process_pdf_ingress


def test_pdf_hidden_sanitize():
    sample = b"VISIBLE:hello\nHIDDEN:secret\nVISIBLE:world"
    text, hits, debug = pdf_sanitize_for_downstream(sample)
    assert text == "hello\nworld"
    assert hits and hits[0]["tag"] == "inj:hidden_text_pdf"
    assert debug["spans_count"] == 1
    assert debug["samples"] == ["secret"]


def test_process_pdf_ingress():
    sample = b"VISIBLE:hi\nHIDDEN:top"
    res = process_pdf_ingress(sample)
    assert res["text"] == "hi"
    assert res["rule_hits"]
    assert res["debug"]["pdf_hidden"]["spans_count"] == 1
