"""Utilities for loading and merging YAML-based policy packs."""

from __future__ import annotations

import hashlib
import io
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import yaml

PACKS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "..",
    "policies",
    "packs",
)
PACKS_DIR = os.path.normpath(PACKS_DIR)


@dataclass(frozen=True)
class PackRef:
    """Reference to a policy pack on disk."""

    name: str
    path: str


def _resolve_pack_path(name: str) -> PackRef:
    """Resolve a pack name to a YAML file stored under ``policies/packs``."""

    candidates = [
        os.path.join(PACKS_DIR, f"{name}.yaml"),
        os.path.join(PACKS_DIR, f"{name}.yml"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return PackRef(name=name, path=candidate)
    raise FileNotFoundError(
        f"Policy pack not found: {name} (searched {candidates})",
    )


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

    ref = _resolve_pack_path(name)
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


__all__ = ["PackRef", "PACKS_DIR", "load_pack", "merge_packs"]
