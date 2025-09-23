# Security Policy

We take security seriously. Please follow the guidance below to report vulnerabilities safely.

## Supported Versions
- **Main branch** and the latest release candidates (e.g., `v1.0.0-rcX`)
- Once a stable `v1.0.0` is cut, the latest minor release line will be supported.

## Reporting a Vulnerability
- **Private report (preferred):** Use GitHub **Security Advisories** to open a private report to the maintainers:
  - Go to **Security → Advisories → Report a vulnerability** in this repo.
- **If Security Advisories are unavailable:** Open a new issue **without sensitive details**, state that you found a potential vulnerability, and ask a maintainer to convert it to a private discussion. We’ll move the conversation off public channels quickly.

Please provide:
- A clear description of the issue and its impact.
- Minimal steps to reproduce (PoC).
- Affected versions/commit(s) if known.
- Any suggested remediation or workaround.

## Disclosure & SLA
- We aim to acknowledge reports **within 3 business days**.
- We’ll collaborate to validate, assess impact, and prepare a fix.
- We prefer **coordinated disclosure**: we’ll propose a timeline (often 14–30 days, depending on severity) to release a fix and publish an advisory.

## Scope Notes
- This project is an API/middleware for policy enforcement around model I/O. If your finding involves third-party models, clouds, or infrastructure **outside this repo**, please report to those vendors.

## Hardening References
- CI includes hygiene/audit steps; see `docs/repo-audits.md`.
- Enforcement posture and security model: `docs/security-model.md`.
- Release checklist and artifact attachment: `docs/release-checklist.md`.
