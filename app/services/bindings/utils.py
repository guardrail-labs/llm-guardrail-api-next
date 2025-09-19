from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Dict, List, Optional


def compute_version_for_path(path: str) -> str:
    """Return a short hash fingerprint for the binding target path."""
    try:
        file_path = Path(path)
        if file_path.is_file():
            data = file_path.read_bytes()
            return hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        pass
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]


def read_policy_version(path: str) -> Optional[str]:
    """Best-effort extraction of ``policy_version`` metadata from YAML."""
    try:
        import yaml
    except Exception:
        return None

    try:
        loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            for key in ("policy_version", "version"):
                value = loaded.get(key)
                if isinstance(value, (str, int, float)):
                    return str(value)
    except Exception:
        return None
    return None


def propagate_bindings(bindings: List[Dict[str, str]]) -> None:
    """Push updated bindings into in-process caches (best effort)."""
    module_candidates = [
        "app.services.rulepacks.bindings",
        "app.services.rulepacks_bindings",
        "app.services.bindings",
        "app.policy.bindings",
        "app.services.rulepacks_engine",
    ]
    func_candidates: List[str] = [
        "set_bindings",
        "apply_bindings",
        "update_bindings",
        "install_bindings",
    ]
    for module_name in module_candidates:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        for func_name in func_candidates:
            func = getattr(module, func_name, None)
            if func and callable(func):
                try:
                    func(bindings)
                    return
                except Exception:
                    pass
        for attr in ("BINDINGS", "_BINDINGS"):
            if hasattr(module, attr):
                try:
                    setattr(module, attr, bindings)
                    return
                except Exception:
                    pass
