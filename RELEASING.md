# Releasing

## Versioned release (Docker `release.yml` runs on tags)
1. Update `README.md` if API changed.
2. Create a tag (semver): `v0.1.0`, `v0.1.1`, etc.
3. Push the tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

The Release workflow builds and pushes:

<DOCKERHUB_USERNAME>/llm-guardrail-api:<version>

<DOCKERHUB_USERNAME>/llm-guardrail-api:latest

## Edge image (manual)

Go to Actions → Docker Edge → Run workflow.

Requires secrets: DOCKERHUB_USERNAME, DOCKERHUB_TOKEN.

