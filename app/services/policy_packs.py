"""Utilities for loading and merging YAML-based policy packs."""

from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

# Backward/forward-compatible search roots (ordered by precedence)
_PACKS_DIRS: List[Path] = [
    Path("policies/packs"),
    Path("policy/packs"),
]


def _legacy_packs_dir() -> Path:
    base = Path(os.path.dirname(os.path.dirname(__file__))) / ".." / "policies" / "packs"
    return Path(os.path.normpath(base))


# Preserve the legacy constant for callers that still import it directly.
PACKS_DIR = str(_legacy_packs_dir())


def _existing_dirs() -> List[Path]:
    """Return the subset of known pack directories that exist."""

    dirs: List[Path] = []
    seen: set[Path] = set()
    project_root = Path(__file__).resolve().parent.parent.parent
    for root in _PACKS_DIRS:
        candidates: List[Path] = []
        if root.is_absolute():
            candidates.append(root)
        else:
            candidates.append(Path.cwd() / root)
            project_candidate = project_root / root
            if project_candidate not in candidates:
                candidates.append(project_candidate)
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_dir():
                    resolved = candidate.resolve(strict=False)
                    if resolved in seen:
                        break
                    seen.add(resolved)
                    dirs.append(resolved)
                    break
            except Exception:
                continue
    return dirs


def resolve_pack_path(name: str) -> Optional[Path]:
    """Resolve a policy pack name to a concrete YAML path."""

    safe = name.strip()
    if safe.endswith(".yaml"):
        safe = safe[: -len(".yaml")]
    elif safe.endswith(".yml"):
        safe = safe[: -len(".yml")]
    candidates = [f"{safe}.yaml", f"{safe}.yml"]
    for root in _existing_dirs():
        for fname in candidates:
            path = root / fname
            try:
                if path.exists() and path.is_file():
                    return path
            except Exception:
                continue
    return None


def list_available_packs() -> List[Tuple[str, Path]]:
    """Enumerate available packs de-duplicated by name respecting precedence."""

    seen: set[str] = set()
    out: List[Tuple[str, Path]] = []
    for root in _existing_dirs():
        try:
            for pack in sorted(root.glob("*.y*ml")):
                name = pack.stem
                if name in seen:
                    continue
                seen.add(name)
                out.append((name, pack))
        except Exception:
            continue
    return out


@dataclass(frozen=True)
class PackRef:
    """Reference to a policy pack on disk."""

    name: str
    path: str


def load_pack_text(name: str) -> str:
    """Return the raw YAML text for the given pack name."""

    path = resolve_pack_path(name)
    if path is None:
        raise FileNotFoundError(f"policy pack not found: {name}")
    return path.read_text(encoding="utf-8")


def _deep_merge(a: Any, b: Any) -> Any:
    """Recursively merge ``b`` into ``a`` producing a new structure."""

    if isinstance(a, dict) and isinstance(b, dict):
        out: Dict[str, Any] = {}
        keys = set(a) | set(b)
        for key in keys:
            if key in a and key in b:
                out[key] = _deep_merge(a[key], b[key])
            elif key in a:
                out[key] = a[key]
            else:
                out[key] = b[key]
        return out
    if isinstance(a, list) and isinstance(b, list):
        return list(a) + list(b)
    return b


def load_pack(name: str) -> Tuple[PackRef, Dict[str, Any], bytes]:
    """Load a single pack by ``name``.

    Returns the pack reference, parsed data, and raw bytes of the file.
    """

    path = resolve_pack_path(name)
    if path is None:
        raise FileNotFoundError(f"policy pack not found: {name}")
    ref = PackRef(name=name, path=str(path))
    with io.open(ref.path, "rb") as fh:
        raw = fh.read()
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Pack {name} is not a dict at top-level")
    return ref, data, raw


def merge_packs(names: Iterable[str]) -> Tuple[Dict[str, Any], str, List[PackRef]]:
    """Merge multiple packs in ``names`` order.

    Later packs override earlier ones. Returns the merged policy, a
    deterministic version hash, and the resolved pack references.
    """

    merged: Dict[str, Any] = {}
    digest = hashlib.sha256()
    refs: List[PackRef] = []

    for name in names:
        ref, data, raw = load_pack(name)
        refs.append(ref)
        digest.update(ref.name.encode("utf-8") + b"\x00" + raw)
        merged = _deep_merge(merged, data)

    version = digest.hexdigest()
    return merged, version, refs


__all__ = [
    "PackRef",
    "PACKS_DIR",
    "load_pack",
    "load_pack_text",
    "merge_packs",
    "list_available_packs",
    "resolve_pack_path",
]
