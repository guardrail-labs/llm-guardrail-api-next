from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class WebhookJob:
    url: str
    method: str
    headers: Dict[str, str]
    body: bytes
    attempt: int
    created_at_s: float
    last_error: Optional[str] = None

    def to_json(self) -> str:
        data = asdict(self)
        data["body"] = self.body.decode("utf-8", errors="ignore")
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def from_json(raw: str) -> "WebhookJob":
        data = json.loads(raw)
        body = data.get("body", "")
        return WebhookJob(
            url=data["url"],
            method=data["method"],
            headers=data.get("headers", {}),
            body=str(body).encode("utf-8"),
            attempt=int(data.get("attempt", 0)),
            created_at_s=float(data.get("created_at_s", time.time())),
            last_error=data.get("last_error"),
        )
