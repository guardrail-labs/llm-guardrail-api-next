#!/usr/bin/env python3
import re
import sys
import pathlib
import json

WORKFLOWS_DIR = pathlib.Path(".github/workflows")
PINNED_SHA = re.compile(r"@([0-9a-f]{40})$")
USES_LINE = re.compile(r"^\s*uses:\s*([^@]+)@(.+)$")

def scan():
    results = []
    for y in WORKFLOWS_DIR.glob("*.yml"):
        lines = y.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines, 1):
            m = USES_LINE.match(line)
            if not m:
                continue
            action, ref = m.group(1).strip(), m.group(2).strip()
            if not PINNED_SHA.search(ref):
                results.append({"file": str(y), "line": i, "action": action, "ref": ref})
    return results

def main():
    unpinned = scan()
    # Write machine-readable JSON for artifact consumers
    with open("unpinned-actions.json", "w", encoding="utf-8") as f:
        json.dump(unpinned, f, indent=2)
    # Write human-friendly Markdown
    with open("unpinned-actions.md", "w", encoding="utf-8") as f:
        if not unpinned:
            f.write("# Unpinned Actions Audit\n\n✅ All GitHub Actions are pinned to commit SHAs.\n")
        else:
            f.write("# Unpinned Actions Audit\n\nThe following workflow steps are not pinned to a 40-char commit SHA:\n\n")
            for r in unpinned:
                f.write(f"- `{r['file']}:{r['line']}` — **{r['action']}@{r['ref']}**\n")
            f.write("\n## Why pin?\nPinning `uses:` to a commit SHA reduces supply-chain risk from action tag hijacks or force-pushes.\n")
            f.write("\n## How to pin\n1) Find the action’s release/tag page.\n2) Copy the commit SHA for the desired version.\n3) Replace `@vX` with `@<40-hex-sha>`.\n")
    print(f"Wrote unpinned-actions.md with {len(unpinned)} item(s).")

if __name__ == "__main__":
    sys.exit(main())
