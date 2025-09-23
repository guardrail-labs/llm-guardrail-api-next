# Contributing

Thanks for your interest in contributing! This document explains how to set up a dev
environment, run checks locally, and submit changes that pass CI smoothly.

## Getting Started
1. **Fork** the repo and create a feature branch from `main`.
2. Ensure you have Python 3.11+ and either `uv` (preferred) or `pip`.
3. Install deps:
   ```bash
   uv sync
   # or, with pip:
   pip install -e .[dev]
   ```
4. Run the API locally:
   ```bash
   # start an ASGI server using the app factory
    uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000

   # in another terminal:
   curl -s http://127.0.0.1:8000/healthz
   ```

## Development Checks (what CI enforces)
Run these before opening a PR:
```bash
# Lint (ruff) and auto-fix trivial issues
ruff check --fix .

# Types (mypy)
mypy .

# Security lints (bandit)
bandit -q -r .

# Unit tests
pytest -q
```

### Perf smoke (optional, but encouraged before release PRs)
```bash
uv run python tools/perf/bench.py --smoke --json out-smoke.json
uv run python tools/perf/compare.py --baseline out-baseline.json --candidate out-smoke.json
```
See `docs/perf-smoke.md` for details.

## Style & Conventions
- **Python style:** enforced by `ruff`; keep lines ≤ 100 chars.
- **Typing:** public functions should be typed; avoid ambiguous lambdas where mypy struggles.
- **Security:** no `assert` for validation in request paths; return explicit 4xx/5xx as appropriate.
- **Commits/PRs:** keep changes scoped; include a brief “What/Why/Risk/Verify” in the PR description.

## CI & Audits
- CI runs lint, types, tests, and non-blocking repo audits:
  - `gitleaks` and `trufflehog` findings are preserved as artifacts.
  - GitHub Actions pinning audit produces `unpinned-actions.{md,json}`.
  - See `docs/repo-audits.md`.

## Enforcement Posture (for contributors)
The API enforces configured policies **in-band** around model I/O. When policies are active,
disallowed outputs are intercepted and mitigated (block/clarify/redact) before returning to the
client. Administrators must enable/maintain the appropriate packs. See:
- `README.md` → Enforcement posture
- `docs/security-model.md`

## Enterprise Tests (opt-in)
Enterprise tests are gated and do not run on public CI by default.
Local:
```bash
pip install fastapi pyyaml
pytest -m enterprise --run-enterprise
```
CI runs on a self-hosted runner/image when labeled or manually dispatched.
See `docs/enterprise-tests.md`.

## Releases
This repo keeps end-user docs in `README.md` and maintainer steps in:
- `RELEASING.md` → points to `docs/release-checklist.md`
- Draft release notes stub: `docs/release-notes-stub-rc1.md`

## Reporting Security Issues
Please **do not** open public issues for vulnerabilities. Use GitHub Security Advisories
or follow the process in `SECURITY.md`.
