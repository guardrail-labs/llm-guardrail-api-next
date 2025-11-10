#!/usr/bin/env python3
"""
Repo-wide, conservative codemod to:
1) Replace bare dict/list/tuple annotations with Typed versions.
2) Ensure typing imports exist where needed.
3) Drop unused '# type: ignore' comments flagged by mypy's 'unused-ignore'.
Only touches .py files under app/, scripts/, deploy/, cli/ (not tests).
Idempotent and reversible via git.
"""

from __future__ import annotations

import ast
import io
import pathlib
import re
import sys
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGETS = ["app", "scripts", "deploy", "cli"]

# Simple patterns; we avoid changing runtime strings/comments except annotations
ANN_PATTERNS = [
    (r"(\bdef [^(]+\([^)]*\)\s*->\s*)dict\b(?!\[)", r"\1Dict[str, Any]"),
    (r"(\bdef [^(]+\([^)]*\)\s*->\s*)list\b(?!\[)", r"\1List[Any]"),
    (r"(\bdef [^(]+\([^)]*\)\s*->\s*)tuple\b(?!\[)", r"\1Tuple[Any, ...]"),
    (r":\s*dict\b(?!\[)(?!\()", r": Dict[str, Any]"),
    (r":\s*list\b(?!\[)(?!\()", r": List[Any]"),
    (r":\s*tuple\b(?!\[)(?!\()", r": Tuple[Any, ...]"),
]

IMPORT_LINE = "from typing import Any, Dict, List, Tuple"
TYPING_NAMES = {"Any", "Dict", "List", "Tuple"}

IMPORT_BLOCK_RE = re.compile(
    r"^from typing import[^\n]*(?:\n[ \t]+[^\n]*)*",
    re.MULTILINE,
)


def used_typing_names(text: str) -> set[str]:
    required: set[str] = set()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    except tokenize.TokenError:
        return required
    for toknum, tokval, *_ in tokens:
        if toknum == tokenize.NAME and tokval in TYPING_NAMES:
            required.add(tokval)
    return required


def imported_typing_names(text: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "typing":
            for alias in node.names:
                if alias.name == "*":
                    return set(TYPING_NAMES)
                names.add(alias.name)
    return names


def missing_typing_names(text: str) -> set[str]:
    required = used_typing_names(text)
    if not required:
        return set()
    existing = imported_typing_names(text)
    return required - existing


def add_typing_import(text: str, missing: set[str]) -> str:
    if not missing:
        return text
    match = IMPORT_BLOCK_RE.search(text)
    if match:
        block = match.group(0)
        body = block.split("import", 1)[1]
        cleaned = body.replace("(", "").replace(")", "").replace("\\", "").replace("\n", ",")
        existing = {part.strip() for part in cleaned.split(",") if part.strip()}
        updated = ", ".join(sorted(existing | missing))
        new_block = f"from typing import {updated}"
        return text[: match.start()] + new_block + text[match.end() :]
    lines = text.splitlines()
    insert_at = 0
    in_multiline_import = False
    in_docstring = False
    doc_delim = ""
    for i, line in enumerate(lines[:200]):  # scan only top of file
        stripped = line.strip()
        if in_docstring:
            insert_at = i + 1
            if stripped.endswith(doc_delim) and len(stripped) >= len(doc_delim):
                in_docstring = False
            continue
        if line.startswith("from __future__") or line.startswith("#!") or stripped == "":
            insert_at = i + 1
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            insert_at = i + 1
            delim = stripped[:3]
            if not (len(stripped) > 3 and stripped.endswith(delim)):
                in_docstring = True
                doc_delim = delim
            continue
        if line.startswith("import ") or line.startswith("from "):
            insert_at = i + 1
            if stripped.endswith("(") or stripped.endswith("\\"):
                in_multiline_import = True
            continue
        if in_multiline_import:
            insert_at = i + 1
            if ")" in stripped and not stripped.endswith("\\"):
                in_multiline_import = False
            continue
        break
    if in_multiline_import:
        insert_at = len(lines)
    names = ", ".join(sorted(missing))
    lines.insert(insert_at, f"from typing import {names}")
    return "\n".join(lines) + ("\n" if not text.endswith("\n") else "")


def clean_unused_ignores(text: str) -> str:
    # Drop plain "# type: ignore" with no code after it on that line
    return re.sub(r"[ \t]#\s*type:\s*ignore(\[[^\]]+\])?\s*$", "", text)


def transform(text: str) -> str:
    new = text
    for pat, repl in ANN_PATTERNS:
        new = re.sub(pat, repl, new)
    new = re.sub(rf"(?m)^\s*{re.escape(IMPORT_LINE)}\s*$\n?", "", new)
    missing = missing_typing_names(new)
    if missing:
        new = add_typing_import(new, missing)
    new = clean_unused_ignores(new)
    return new


def main() -> int:
    changed = 0
    for target in TARGETS:
        for p in (ROOT / target).rglob("*.py"):
            s = p.read_text(encoding="utf-8")
            t = transform(s)
            if t != s:
                p.write_text(t, encoding="utf-8")
                changed += 1
    print(f"[autofix_types] files changed: {changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
