# Release Checklist

- [ ] Merge all green PRs for milestone.
- [ ] Update `CHANGELOG.md` & `VERSION`.
- [ ] Run `scripts/tag_release.sh vX.Y.Z` and push tag.
- [ ] Verify GitHub Actions created Release + GHCR image.
- [ ] Sanity run: `bench/runner.py` basic_mixed against staging.
- [ ] Post `docs/UPGRADE.md` highlights to internal channel.
