# Security Policy

**Organization:** Guardrail Labs, LLC  
**Project:** LLM Guardrail Core Runtime  
**Status:** Patent pending

## Supported Versions

- `main` branch and the latest stable release line (e.g., `v1.4.x`)
- Release candidates may receive targeted fixes when necessary.

## Reporting a Vulnerability

**Preferred:** GitHub Security Advisories → _Report a vulnerability_ for this repository.

If Security Advisories are unavailable, open a **minimal** public issue (no sensitive details) stating that you found a potential vulnerability and ask a maintainer to convert it to a private advisory. We will move the conversation off public channels quickly.

Please include:

- Impacted component(s) and a clear description of the issue
- Minimal steps to reproduce (PoC)
- Affected versions/commit(s), if known
- Suggested remediation or workaround, if any

## Disclosure & SLA

- We aim to acknowledge reports within **3 business days**.
- We collaborate to validate, assess impact, and prepare a fix.
- We prefer **coordinated disclosure**; typical timelines are **14–30 days** based on severity.

## Scope Notes

This project is an API/middleware for policy enforcement around model I/O. If your finding involves third-party models, clouds, or infrastructure outside this repo, please also report to those vendors.

## Hardening References

- CI hygiene & audits: `docs/repo-audits.md`
- Enforcement posture & security model: `docs/security-model.md`
- Release checklist & artifact attachment: `docs/release-checklist.md`
