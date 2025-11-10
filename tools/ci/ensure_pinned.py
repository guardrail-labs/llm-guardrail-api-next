#!/usr/bin/env python3
import json
import pathlib
import re
import sys

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

    # Machine-readable JSON for artifact consumers
    with open("unpinned-actions.json", "w", encoding="utf-8") as f:
        json.dump(unpinned, f, indent=2)

    # Human-friendly Markdown
    with open("unpinned-actions.md", "w", encoding="utf-8") as f:
        if not unpinned:
            success_md = (
                "# Unpinned Actions Audit\n\n✅ All GitHub Actions are pinned to commit SHAs.\n"
            )
            f.write(success_md)
        else:
            header_md = (
                "# Unpinned Actions Audit\n\n"
                "The following workflow steps are not pinned to a "
                "40-char commit SHA:\n\n"
            )
            f.write(header_md)

            for r in unpinned:
                f.write(f"- `{r['file']}:{r['line']}` — **{r['action']}@{r['ref']}**\n")

            why_md = (
                "\n## Why pin?\n"
                "Pinning `uses:` to a commit SHA reduces supply-chain risk from "
                "action tag hijacks or force-pushes.\n"
            )
            how_md = (
                "\n## How to pin\n"
                "1) Find the action’s release/tag page.\n"
                "2) Copy the commit SHA for the desired version.\n"
                "3) Replace `@vX` with `@<40-hex-sha>`.\n"
            )
            f.write(why_md)
            f.write(how_md)

    print(f"Wrote unpinned-actions.md with {len(unpinned)} item(s).")


if __name__ == "__main__":
    sys.exit(main())
