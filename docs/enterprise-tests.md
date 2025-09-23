# Enterprise tests (opt-in)

Enterprise tests are marked `@pytest.mark.enterprise` and are **disabled by default**.

## Local
```bash
pip install fastapi pyyaml
pytest -m enterprise --run-enterprise
```

If deps are missing, tests skip gracefully (importorskip/try-except).

## CI
- Workflow: `.github/workflows/enterprise-tests.yml`
- Triggers: add the `run-enterprise` label **or** manual dispatch.
- Runs only on self-hosted runners (or prebuilt container) where `fastapi` and `PyYAML` already exist; the job **verifies** deps instead of installing (proxy-friendly).
