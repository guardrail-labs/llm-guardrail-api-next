# Ensures "import app" works regardless of runner quirks
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import os

# Let tests/CI call admin endpoints without real credentials.
os.environ.setdefault("GUARDRAIL_DISABLE_AUTH", "1")
# If you later want to test authenticated flows, you can also:
os.environ.setdefault("GUARDRAIL_API_KEY", "test-key")

