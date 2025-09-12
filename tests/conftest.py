import os
import sys
from pathlib import Path

# Test env toggles (set before importing app)
os.environ.setdefault("GUARDRAIL_DISABLE_AUTH", "1")
os.environ.setdefault("GUARDRAIL_API_KEY", "test-key")
os.environ.setdefault("METRICS_ROUTE_ENABLED", "1")

# Ensures "import app" works regardless of runner quirks
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
