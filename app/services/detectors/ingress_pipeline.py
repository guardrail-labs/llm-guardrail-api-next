try:
    from app.services.detectors import pdf_sanitize_for_downstream
except Exception:  # fallback if not available
    pdf_sanitize_for_downstream = None


def process_pdf_ingress(pdf_bytes: bytes) -> dict:
    if pdf_sanitize_for_downstream:
        text, rule_hits, debug = pdf_sanitize_for_downstream(pdf_bytes)
        return {"text": text, "rule_hits": rule_hits, "debug": {"pdf_hidden": debug}}
    return {"text": "", "rule_hits": [], "debug": {"pdf_hidden": {"spans_count": 0}}}
