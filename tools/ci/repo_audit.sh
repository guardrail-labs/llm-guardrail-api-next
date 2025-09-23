#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-repo-audit-report.md}"
REPO_NAME="$(basename "$(git rev-parse --show-toplevel 2>/dev/null || echo .)")"
DATE="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"

section() { echo -e "\n## $1\n"; }
note()    { echo "- $1"; }
code()    { printf '\n```\n%s\n```\n\n' "$1"; }
run_or_skip() {
  local title="$1"; shift
  if "$@" > /tmp/audit.tmp 2>&1; then
    section "$title"
    cat /tmp/audit.tmp
  else
    section "$title (SKIPPED/NOISY)"
    echo "Command failed or tool missing. Error output:"
    code "$(cat /tmp/audit.tmp)"
  fi
  rm -f /tmp/audit.tmp || true
}

{
echo "# Repo Audit Report – ${REPO_NAME}"
echo "_Generated: ${DATE}_"

section "Overview"
note "Read-only audit. No files changed; no git history rewritten."
note "Intended for pre-RC1 hygiene and public release readiness."

section "Git Hygiene & Stray Artifacts (dry-runs)"
run_or_skip "Tracked files (summary)" bash -lc 'git status -s || true'
run_or_skip "Ignored/untracked preview (ignored only)" bash -lc 'git clean -ndX || true'
run_or_skip "Ignored/untracked preview (everything)" bash -lc 'git clean -ndx || true'
run_or_skip "Largest blobs in history (top 50)" bash -lc '
  git rev-list --objects --all \
  | git cat-file --batch-check="%(objecttype) %(objectname) %(objectsize) %(rest)" \
  | awk '\''$1=="blob"{print $3/1024/1024 " MB\t" $4}'\'' \
  | sort -nr | head -50 || true
'

section "Secrets Scan (current tree only)"
# Fast patterns (heuristic only). TruffleHog/Gitleaks run later if available.
run_or_skip "Heuristic secrets grep" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n --hidden --iglob "!.git" \
    -e "(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----|xox[baprs]-|password\\s*[:=]|secret\\s*[:=])" || true
'

section "Optional: Deep Secrets (if tools present)"
run_or_skip "trufflehog (filesystem, no history)" bash -lc '
  command -v trufflehog >/dev/null || { echo "trufflehog not installed"; exit 1; }
  trufflehog filesystem --no-update --fail --json . || true
'
run_or_skip "gitleaks (default rules)" bash -lc '
  command -v gitleaks >/dev/null || { echo "gitleaks not installed"; exit 1; }
  gitleaks detect --no-banner -v || true
'

section "Supply Chain & Static Analysis (best-effort)"
run_or_skip "pip-audit (requirements*)" bash -lc '
  command -v pip-audit >/dev/null || { echo "pip-audit not installed"; exit 1; }
  shopt -s nullglob; for f in requirements*.txt; do echo "== $f =="; pip-audit -r "$f" || true; done
'
run_or_skip "bandit (app/)" bash -lc '
  command -v bandit >/dev/null || { echo "bandit not installed"; exit 1; }
  bandit -q -r app/ || true
'
run_or_skip "vulture dead-code (app/)" bash -lc '
  command -v vulture >/dev/null || { echo "vulture not installed"; exit 1; }
  vulture app/ || true
'

section "GitHub Workflows: permissions & pins"
run_or_skip "Workflows needing pinning (uses: without @sha)" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n ".github/workflows" -e "uses:\\s*[^@]+@[^0-9a-f]" || true
'
run_or_skip "Workflows with explicit permissions blocks" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n ".github/workflows" -e "permissions:" -n || true
'

section "Terraform/Helm Lints (if available)"
run_or_skip "tflint" bash -lc 'command -v tflint >/dev/null || { echo "tflint not installed"; exit 1; }; tflint || true'
run_or_skip "terraform validate (examples/ha)" bash -lc '
  command -v terraform >/dev/null || { echo "terraform not installed"; exit 1; }
  test -d terraform/examples/ha || { echo "terraform/examples/ha not found"; exit 0; }
  terraform -chdir=terraform/examples/ha validate || true
'
run_or_skip "yamllint policies/" bash -lc '
  command -v yamllint >/dev/null || { echo "yamllint not installed"; exit 1; }
  test -d policies || { echo "policies/ not found"; exit 0; }
  yamllint policies/ || true
'

section "Config Foot-guns (grep heuristics)"
run_or_skip "Debug/insecure toggles present?" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n app/ -e "DEBUG\\s*=\\s*True|allow_insecure|verify=False|insecure" || true
'
run_or_skip "Hard-coded secrets?" bash -lc $'
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n app/ -e "(SECRET|TOKEN|API_KEY)\s*=[\"\'][^\"\' ]+[\"\']" || true
'
run_or_skip "Admin routes (ensure protected)" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n app/routes -e "@(router|app)\\.(get|post|any)\\(\"/admin" || true
'

section "Docs & Notes"
run_or_skip "TODO/FIXME outside tests" bash -lc '
  command -v rg >/dev/null || { echo "ripgrep (rg) not installed"; exit 1; }
  rg -n -e "TODO|FIXME|HACK|XXX" -g "!**/tests/**" || true
'
echo
echo "> Reminder one-liner for README:"
code "Even if your LLM misbehaves, Guardrail ensures unsafe outputs never leave the API boundary."

} | tee "$OUT"
echo "Wrote report to $OUT"
