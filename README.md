# LLM Guardrail API - Patent Pending 

**A firewall for prompts and model outputs.**  
Sits between submitters (humans/agents) and your LLMs to **detect & block unsafe intent**, **sanitize secrets/PII**, and **prove compliance** with **signed audits** and **directional observability** (ingress vs egress).

> **Ten-second pitch:** Drop this in front of your models to stop jailbreaks & secret leaks without retraining, see **who is risky (user) vs what is risky (model)**, and show a dashboard that executives understand.

---

## Why teams use this

- **Direction-labeled risk:** ingress vs egress metrics expose user-driven attacks vs model drift.
- **Intent-first detection:** not just regex; verifier routing for gray areas.
- **Redactions that stick:** secrets/PII/injection markers scrubbed on the way in **and** out.
- **Per-tenant/bot policy packs:** bind different rules without redeploying.
- **Signed audit trail:** minimal, HMAC-signed events ready for your SIEM.
- **Multimodal v1:** OCR for images/PDFs → same pipeline as text.

---

## Architecture (bird’s-eye)



[client/app] --(prompt/files)--> [Guardrail API]
| |
| (verify/clarify)|--> [Verifier LLMs]
| |
|<--(sanitized allow/deny)--------|
|
+--> [LLM Provider(s)] --(response)--> [Guardrail Egress Check] --(sanitized/deny)--> back to client

  └── Audit Receiver (signed events) ──> Prometheus ──> Grafana dashboards


**Key flows**
- **Ingress:** detect illicit intent/jailbreak/secrets → allow/clarify/deny + redactions.
- **Egress:** catch model leaks (e.g., keys, private-key envelopes) in real time; stream-safe.
- **Bindings:** resolve `{tenant, bot} → rules.yaml` with wildcard precedence.
- **Observability:** `guardrail_*` metrics incl. **family totals** and **redactions by mask**.

---

## Quick start

- **Install**: one command → stack up with API + Audit + Prom + Grafana  
  → See [`docs/Quickstart.md`](docs/Quickstart.md)
- **Operate**: policies, bindings, verifier, threat feed, metrics  
  → See [`docs/OperatorGuide.md`](docs/OperatorGuide.md)
- **Integrate**: OpenAI-compatible endpoints (`/v1/*`)  
  → See [`docs/IntegrationOpenAI.md`](docs/IntegrationOpenAI.md)
- **Demo**: copy/paste POC script
  → See [`docs/DemoScript.md`](docs/DemoScript.md)

## Configuration
See [CONFIG.md](./CONFIG.md) for all tunables and defaults. Values are normalized by
`app/services/config_sanitizer.py` to ensure safe, predictable behavior.

### Hidden-text detection
The service now includes stdlib-only detectors for **HTML** and **DOCX** hidden text
(parallel to our PDF checks). See `app/services/detect/hidden_text.py` and tests under
`tests/detect/` for examples (display:none, visibility:hidden, font-size:0, w:vanish).

## Admin / Bindings
See [BINDINGS.md](./BINDINGS.md) for conflict detection rules and examples.

## Logging
Use `install_json_logging(app)` to enable structured JSON logs. The installer
clears duplicate handlers on reload and emits one access log per request.

## Compression
Outbound compression uses a custom streaming-safe `GZipMiddleware` placed ahead
of Starlette's builtin GZip. This avoids double-encoding and preserves
`text/event-stream` responses. Toggled via:

- `COMPRESSION_ENABLED=1`
- `COMPRESSION_MIN_SIZE_BYTES=1024`

## Egress filter
`EgressGuardMiddleware` redacts SSNs and email addresses from JSON or plaintext
responses. Disable with `EGRESS_FILTER_ENABLED=0`.

### Clarify-first (ingress)
- `CLARIFY_HTTP_STATUS` (default `422`)
- `CLARIFY_MESSAGE`
- `CLARIFY_QUESTIONS` (semicolon-separated)
Behavior: classifier/verifier ambiguous/timeout → standardized clarify response with
`incident_id`, headers set to `decision=clarify`, no tool/LLM execution.

### Egress modes
- `EGRESS_FILTER_ENABLED=1` (default on)
- `EGRESS_SUMMARIZE_ENABLED=0` (optional)
- `EGRESS_POLICY_CHECK_ENABLED=0` (optional)
- `EGRESS_STREAMING_REDACT_ENABLED=0` — enable streaming redaction for text/event-stream & text/*
- `EGRESS_STREAMING_OVERLAP_CHARS=2048` — overlap window to catch cross-chunk matches
Pipeline: redaction → optional summarize → optional policy-check (annotative; does
**not** block). Streaming (SSE/chunked) is **never** buffered or transformed.

### Observability
- New docs: `docs/observability.md`
- Grafana: import `dashboards/grafana_guardrail.json`

### Admin — Active Policy View
- `GET /admin/policies/active` returns:
  - `policy_version`
  - `env_toggles` (CORS, EGRESS_*, CLARIFY_*)
  - `decision_map` (classifier/verifier → action)

### Rulepacks (Enforcement)
- `RULEPACKS_ENFORCE=0|1`
- `RULEPACKS_ACTIVE=hipaa,gdpr`
- `RULEPACKS_DIR=rulepacks`
- `RULEPACKS_INGRESS_MODE=clarify|block|annotate`
- `RULEPACKS_EGRESS_MODE=enforce|annotate`

When enabled, egress redactions from rulepacks are merged with the built-in patterns.
Ingress controls can optionally clarify or block before execution.

### Admin Auth (optional)
- `GUARDRAIL_DISABLE_AUTH=1` — bypass auth (default in CI/tests)
- `ADMIN_UI_AUTH=1` — enable auth for admin JSON endpoints
- `ADMIN_UI_TOKEN=<string>` — Bearer token required when auth is enabled

**Behavior:**
- `/admin/ui` (HTML) is public; it uses a token (if provided) when fetching JSON from:
  - `/admin/policies/active`, `/admin/policies/preview`
  - `/admin/rulepacks`, `/admin/rulepacks/{name}`

Store the token in the Admin UI using the “Admin token” field; the UI saves it to `localStorage` and includes it as `Authorization: Bearer <token>` on API calls.

### Policy Preview (dry-run)
- `POST /admin/policies/preview` with:
  ```json
  { "env_overrides": { "EGRESS_SUMMARIZE_ENABLED": "1", "CLARIFY_HTTP_STATUS": "400" } }
  ```

Returns preview (as active would look) + changed diff. No changes are applied.

## Verifier latency budgets
Set `VERIFIER_LATENCY_BUDGET_MS` to bound verifier calls. Exceeding the budget
returns a `timeout` outcome that policy maps to a deny decision.

---

## Feature checklist

- ✅ Directional observability (ingress vs egress families; tenant/bot breakdowns)
- ✅ OCR v1 (images/PDF → text → same pipeline)
- ✅ Admin bindings (`/admin/bindings`) with wildcard resolution
- ✅ One-command packaging (compose + health + dashboards)
- ✅ Docs & demo (copy/paste to first win)
- 🛠 Verifier specializations & adjudication logs (roadmap)
- 🛠 Admin UI & auto-mitigation toggles (roadmap)

---

## Playbooks

Copy-paste demos that hit deny/redaction and show metrics:
- [`examples/playbooks/hr.md`](examples/playbooks/hr.md)
- [`examples/playbooks/healthcare_hipaa.md`](examples/playbooks/healthcare_hipaa.md)
- [`examples/playbooks/finserv.md`](examples/playbooks/finserv.md)
- [`examples/playbooks/secops.md`](examples/playbooks/secops.md)

---

## License

Apache-2.0 (see `LICENSE`).

## Admin / Demo UI
A minimal admin panel is available at `/admin` to explore bindings, validation,
active policy resolution, and metrics. See [ADMIN_UI.md](./ADMIN_UI.md).
