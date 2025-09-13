from __future__ import annotations

import os
from typing import Any, Dict, cast

import yaml

RULEPACK_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "rulepacks")


def load_rulepack(name: str) -> Dict[str, Any]:
    path = os.path.join(RULEPACK_DIR, f"{name}.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return cast(Dict[str, Any], yaml.safe_load(f))


def list_rulepacks() -> Dict[str, str]:
    return {"hipaa": "HIPAA scaffolding", "gdpr": "GDPR scaffolding"}

