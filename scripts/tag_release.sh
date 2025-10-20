#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 vX.Y.Z[-rcN]" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "repo dirty; commit or stash first" >&2
  exit 1
fi

VER="${TAG#v}"
echo "$VER" > VERSION

if ! grep -q "\[$VER\]" CHANGELOG.md; then
  echo "CHANGELOG.md missing section for [$VER]" >&2
  exit 1
fi

git add VERSION
if git diff --cached --quiet; then
  echo "VERSION already set to $VER" >&2
else
  git commit -m "chore(release): $TAG"
fi
git tag -a "$TAG" -m "Release $TAG"
echo "created tag $TAG — push with: git push origin $TAG"
