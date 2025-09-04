# LLM Guardrail API — Showcase Pack

This pack contains everything you need to present the Guardrail API quickly and professionally: a one-pager, README hero section, slide deck outline, demo narratives, sample rules, a press/demo FAQ, and an outreach email template.

---

## 1) One-Pager (copy to PDF or paste into slides)

**What it is**
A production-ready, LLM-agnostic security layer that intercepts prompts and model outputs to enforce policy, redact sensitive data, and provide verifiable audit trails.

**Why it matters**
Enterprises need consistent, explainable safety controls across providers (OpenAI, Anthropic, Azure, local). This API standardizes policy enforcement with transparent provenance and optional verifier routing for gray-areas.

**Key features**

* Ingress & egress enforcement with multimodal redaction (text, files, images, audio, PDFs)
* Configurable policies (PII, secrets, illicit content, jailbreaks)
* OpenAI-compatible proxy routes; can also be imported as a library
* Structured debug provenance (`debug.sources`, redaction spans, hashes)
* Verifier MVP for ambiguous intent (provider-agnostic, mock ready)
* Metrics, audit forwarding, quotas, rate limiting, tracing
* Docker/K8s ready, `.env` and `rules.yaml` configurable

**Outcomes**

* Prevent data leakage and policy violations
* Explainable decisions and forensic traceability
* Rapid integration regardless of LLM vendor

---

## 2) README Hero (drop-in block)

\````md
# LLM Guardrail API

Intercept • Enforce • Redact • Verify — for any LLM

[![CI](https://img.shields.io/badge/tests-green-success)]() [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)]()

A production-ready, LLM-agnostic security layer for prompts and responses.

- **Policy enforcement** for PII, secrets, illicit content, and jailbreaks
- **Multimodal redactions** (text, files, images, audio, PDFs)
- **OpenAI-compatible** proxy routes (or import as a library)
- **Transparent provenance** via `debug.sources` and redaction spans
- **Verifier** path for gray-areas (block/clarify/allow)

**Quickstart**
```bash
docker compose up --build
curl -s http://localhost:8000/health | jq
```

**Demo**

```bash
# PII redaction
docker compose up -d
curl -s -X POST http://localhost:8000/guardrail/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"text":"Email me at jane.doe@example.com"}' | jq
```
\````

---

## 3) Slides Outline (10–12 minutes)
**Slide 1 – Problem**: Safety erosion & inconsistent policies across LLM vendors; need explainability.  
**Slide 2 – Solution**: Guardrail API: intercept, enforce, redact, verify (agnostic, observable).  
**Slide 3 – Architecture**: Mermaid diagram (ingress→policy→verifier→egress; metrics/audit/debug).  
**Slide 4 – Features**: Multimodal redactions, OpenAI-compat, provenance, quotas/metrics.  
**Slide 5 – Demo**: 3 curls: PII redaction, injection default, verifier trace (with `X-Debug: 1`).  
**Slide 6 – Integration**: Proxy vs library; Docker/K8s; `.env` + `rules.yaml`.  
**Slide 7 – Compliance & Audit**: Provenance (`debug.sources`), spans, hashes, audit forwarding.  
**Slide 8 – Roadmap**: Provider adapters for verifier, tenant defaults, simple dashboard.  
**Slide 9 – Ask**: Pilot partners / funding / roles.  
**Slide 10 – Contact**: Repo link, email, availability.

---

## 4) Demo Narratives (talk track)
- **PII Redaction**: “Here’s the same input with PII removed on ingress. Note the rule hit and the span.”
- **Injection Default**: “Dangerous phrasing triggers the default policy; we can flip to clarify via env.”
- **Provenance**: “`debug.sources` shows origin, modality, file metadata, sha256, and redaction spans—no raw content.”
- **Verifier MVP**: “Gray-area requests route to a classifier for allow/clarify/block, traced in debug.”
- **Egress Redaction**: “Outgoing content gets scrubbed before leaving the model boundary.”

---

## 5) Sample `rules.yaml` (minimal, safe-default)
\```yaml
defaults:
  injection_action: block

families:
  pii:
    email:
      pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
      redaction: "[REDACTED:EMAIL]"
    phone:
      pattern: "\\b(?:\\+?1[-.\\s]?)?(?:\\(\\d{3}\\)|\\d{3})[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b"
      redaction: "[REDACTED:PHONE]"
  secrets:
    openai_key:
      pattern: "sk-[A-Za-z0-9]{16,}"
      redaction: "[REDACTED:OPENAI_KEY]"
  injection:
    prompt:
      pattern: "(?i)(ignore previous|jailbreak|bypass)"
      on_match: null  # defer to defaults: block
\```

---

## 6) Press / Demo FAQ (short answers)

**Q: Is this tied to one model?**
A: No—OpenAI-compatible proxy + library mode keep it LLM-agnostic.

**Q: Can we explain why a decision happened?**
A: Yes—`debug.sources` shows origin, modality, sha256, rule hits, and redaction spans.

**Q: Does it change the model’s behavior?**
A: It constrains inputs/outputs via policy and redactions; the model remains a black box behind the API.

**Q: What about latency/cost?**
A: Deterministic rules are fast; verifier is optional and budgeted via timeouts and per-request caps.

**Q: How do we deploy?**
A: Docker/K8s with `.env` + `rules.yaml`. Quickstart in README; example manifests included.

**Q: How do we extend policies?**
A: Add/modify families in `rules.yaml`. Per-rule `on_match` overrides, plus global defaults via env.

---

## 7) Outreach Email Template (investors/employers)

Subject: Guardrail API — Show-ready LLM Safety Layer (Demo inside)

Hi <Name>,

We’ve built a production-shaped **LLM Guardrail API** that enforces safety policies across any model. It intercepts prompts/responses, **redacts sensitive data**, and **explains decisions** with structured provenance. An optional verifier path handles gray-area intent.

**What you’ll see in a 5-min demo**

* PII redaction on ingress, egress scrubbing on outputs
* Default policy blocking for injection/jailbreak with a live toggle to clarify
* `debug.sources` provenance and a verifier trace

**Why it matters**

* Consistent, explainable safety across providers (OpenAI, Anthropic, Azure, local)
* Audit-ready with spans and hashes; Docker/K8s deployment

If interesting, I can share a short video or run a live demo. Would next week work for a quick walkthrough?

Best, <Your Name>

---

## 8) Slide Export Tips

* Use the Mermaid diagram; export to PNG for decks.
* Keep code blocks large enough to read; highlight the redaction spans visually.
* End with the three-curl demo slide + QR code to the repo.

