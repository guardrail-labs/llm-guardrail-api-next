# Releasing

1. Make sure `main` is green.
2. Pick the next semver tag, e.g. `v0.2.0`.
3. Create the tag in GitHub UI or locally:

   ```bash
   git switch main
   git pull
   git tag v0.2.0
   git push origin v0.2.0
   ```

